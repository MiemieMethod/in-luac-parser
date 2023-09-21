#![feature(ptr_sub_ptr)]
#![feature(lazy_cell)]
#![allow(improper_ctypes_definitions)]

pub mod custom;
pub mod lua51;

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
    combinator::success,
    error::{context, ErrorKind, ParseError},
    multi::{length_count, length_data},
    number::complete,
    Parser,
};
use nom_supreme::{error::*, ParserExt};

fn lua_header(input: &[u8]) -> IResult<&[u8], LuaHeader, ErrorTree<&[u8]>> {
    let (rest, (_, result)) = tuple((
        tag(b"\x1BLua"),
        alt((map(
            tuple((
                tag(b"\x51"),
                be_u8,
                be_u8,
                be_u8,
                be_u8,
                be_u8,
                be_u8,
                be_u8,
            )),
            |(
                _,
                format_version,
                big_endian,
                int_size,
                size_t_size,
                instruction_size,
                number_size,
                number_integral,
            )| LuaHeader {
                lua_version: 0x51,
                format_version,
                big_endian: big_endian != 1,
                int_size,
                size_t_size,
                instruction_size,
                number_size,
                number_integral: number_integral != 0,
                ..Default::default()
            },
        ),)),
    ))(input)?;
    Ok((rest, result))
}

fn must<I, O, E: ParseError<I>, P: Parser<I, O, E>>(
    cond: bool,
    mut parser: P,
) -> impl FnMut(I) -> IResult<I, O, E> {
    move |input| {
        if cond {
            parser.parse(input)
        } else {
            Err(nom::Err::Error(E::from_error_kind(
                input,
                ErrorKind::Switch,
            )))
        }
    }
}

fn lua_int<'a>(header: &LuaHeader) -> impl Parser<&'a [u8], u64, ErrorTree<&'a [u8]>> {
    let intsize = header.int_size;
    alt((
        must(
            intsize == 8,
            map(complete::u64(header.endian()), |v| v as u64),
        ),
        must(
            intsize == 4,
            map(complete::u32(header.endian()), |v| v as u64),
        ),
        must(
            intsize == 2,
            map(complete::u16(header.endian()), |v| v as u64),
        ),
        must(intsize == 1, map(be_u8, |v| v as u64)),
    ))
    .context("integer")
}

fn lua_size_t<'a>(header: &LuaHeader) -> impl Parser<&'a [u8], u64, ErrorTree<&'a [u8]>> {
    let sizesize = header.size_t_size;
    alt((
        must(
            sizesize == 8,
            map(complete::u64(header.endian()), |v| v as u64),
        ),
        must(
            sizesize == 4,
            map(complete::u32(header.endian()), |v| v as u64),
        ),
        must(
            sizesize == 2,
            map(complete::u16(header.endian()), |v| v as u64),
        ),
        must(sizesize == 1, map(be_u8, |v| v as u64)),
    ))
    .context("size_t")
}

fn lua_number<'a>(header: &LuaHeader) -> impl Parser<&'a [u8], LuaNumber, ErrorTree<&'a [u8]>> {
    let int = header.number_integral;
    let size = header.number_size;
    alt((
        must(
            int == true,
            map(
                alt((
                    must(size == 8, map(complete::be_i8, |v| v as i64)),
                    must(size == 4, map(complete::i16(header.endian()), |v| v as i64)),
                    must(size == 2, map(complete::i32(header.endian()), |v| v as i64)),
                    must(size == 1, map(complete::i64(header.endian()), |v| v as i64)),
                )),
                |v| LuaNumber::Integer(v),
            ),
        ),
        must(
            int == false,
            map(
                alt((
                    must(size == 8, map(complete::f64(header.endian()), |v| v as f64)),
                    must(size == 4, map(complete::f32(header.endian()), |v| v as f64)),
                )),
                |v| LuaNumber::Float(v),
            ),
        ),
    ))
    .context("number")
}

pub fn lua_bytecode(input: &[u8]) -> IResult<&[u8], LuaBytecode, ErrorTree<&[u8]>> {
    let (input, header) = lua_header(input)?;
    log::trace!("header: {header:?}");
    let (input, main_chunk) = match header.lua_version {
        0x51 => lua51::lua_chunk(&header).parse(input)?,
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
