#![feature(ptr_sub_ptr)]
#![allow(improper_ctypes_definitions)]

pub mod lua54;

use luac_parser::*;
#[allow(unused_imports)]
use nom::{
    branch::alt,
    bytes::complete::{escaped, tag, take_till, take_until, take_while, take_while_m_n},
    character::{
        complete::{alphanumeric1, char as cchar, multispace0, multispace1, none_of, one_of},
        is_alphabetic, is_newline, is_space,
        streaming::space1,
    },
    combinator::{fail, map, map_res, opt, value},
    number::complete::be_u8,
    sequence::{delimited, tuple},
};
use nom::{
    bytes::complete::take,
    error::{context},
    multi::{length_count},
    number::complete,
    Parser,
};
use nom_supreme::{error::*, ParserExt};
use std::collections::HashMap;

fn lua_header(input: &[u8]) -> IResult<&[u8], LuaHeader, ErrorTree<&[u8]>> {
    let (rest, (_, result)) = tuple((
        tag(b"\x1BLua"),
        alt((map(
            tuple((
                tag(b"\x53"),
                be_u8,
                take(6usize), // LUAC_DATA
                be_u8,
                be_u8,
                be_u8,
                complete::le_i64,
                complete::le_f64,
                be_u8,
            )),
            |(
                 _,
                 format_version,
                 _luac_data,
                 instruction_size,
                 _integer_size, // lua_Integer
                 number_size,
                 _,
                 _,
                 _,
             )| LuaHeader {
                lua_version: LUA54.0,
                format_version,
                big_endian: false,
                int_size: 4,
                size_t_size: 8,
                instruction_size,
                number_size,
                number_integral: false,
                ..Default::default()
            },
        ),)),
    ))(input)?;
    Ok((rest, result))
}

pub fn lua_bytecode(input: &[u8]) -> IResult<&[u8], LuaBytecode, ErrorTree<&[u8]>> {
    let (input, header) = alt((lua_header, luajit::lj_header))(input)?;
    log::trace!("header: {header:?}");
    let (input, main_chunk) = match header.version() {
        LUA51 => lua51::lua_chunk(&header).parse(input)?,
        LUA52 => lua52::lua_chunk(&header).parse(input)?,
        LUA53 => lua53::lua_chunk(&header).parse(input)?,
        LUA54 => lua54::lua_chunk(&header).parse(input)?,
        LUAJ1 | LUAJ2 => luajit::lj_chunk(&header).parse(input)?,
        _ => context("unsupported lua version", fail)(input)?,
    };
    Ok((input, LuaBytecode { header, main_chunk }))
}

pub fn parse_(input: &[u8]) -> anyhow::Result<LuaBytecode> {
    lua_bytecode(input).map(|x| x.1).map_err(|e| {
        anyhow::anyhow!(
            "{:#?}",
            e.map(|e| e.map_locations(|p| unsafe { p.as_ptr().sub_ptr(input.as_ptr()) }))
        )
    })
}

use extism_pdk::*;

#[plugin_fn]
pub fn parse(luac: Vec<u8>) -> FnResult<Vec<u8>> {
    parse_(&luac)
        .map_err(|e| WithReturnCode::from(e))?
        .to_msgpack()
        .map_err(|e| WithReturnCode::from(e))
}