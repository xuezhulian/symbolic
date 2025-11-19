//! Provides SymCache support.
//!
//! This includes a reader and writer for the binary format, as well as helper traits and functions
//! to apply transformations to debugging symbols before they are written to the SymCache.
//!
//! # Structure of a SymCache
//!
//! A SymCache (version 7) contains the following primary kinds of data, written in the following
//! order:
//!
//! 1. Files
//! 2. Functions
//! 3. Source Locations
//! 4. Address Ranges
//! 5. String Data
//!
//! The format uses `u32`s to represent line numbers, addresses, references, and string offsets.
//! Line numbers use `0` to represent an unknown or invalid value. Addresses, references, and string
//! offsets instead use `u32::MAX`.
//!
//! Strings are saved in one contiguous section with each individual string prefixed by 4 bytes
//! denoting its length. Functions and files refer to strings by an offset into this string section,
//! hence "string offset".
//!
//! ## Files
//!
//! A file contains string offsets for its file name, parent directory, and compilation directory.
//!
//! ## Functions
//!
//! A function contains string offsets for its name and compilation directory, a u32 for its entry
//! address, and a u32 representing the source language. The name is non-optional, i.e., the name
//! index should always point to a valid string.
//!
//! ## Address Ranges
//!
//! Ranges are saved as a contiguous list of `u32`s, representing their starting addresses.
//!
//! ## Source Locations
//!
//! A source location in a symcache represents a possibly-inlined copy of a line in a source file.
//! It contains a line number, a reference to a file (see above), a reference to a function (ditto),
//! and a reference to the source location into which this source location was inlined. All of these
//! data except for the function are optional.
//!
//! ## Mapping From Ranges To Source Locations
//!
//! Every range in the SymCache is associated with at least one source location. As mentioned above,
//! each source location may in turn have a reference to a source location into which it is inlined.
//! Conceptually, each address range points to a sequence of source locations, representing a
//! hierarchy of inlined function calls.
//!
//! ### Example
//!
//! The mapping
//!
//! - `0x0001 - 0x002f`
//!   - `trigger_crash` in file `b.c`, line 12
//!   - inlined into `main` in file `a.c`, line 10
//! - `0x002f - 0x004a`
//!   - `trigger_crash` in file `b.c`, line 13
//!   - inlined into `main` in file `a.c`, line 10
//!
//! is represented like this in the SymCache (function/file name strings inlined for simplicity):
//! ```text
//! ranges: [
//!     0x0001 -> 1
//!     0x002f -> 2
//! ]
//!
//! source_locations: [{
//!     file: "a.c"
//!     line: 10
//!     function: "main"
//!     inlined_into: u32::MAX (not inlined)
//! }, {
//!     file: "b.c"
//!     line: 12
//!     function: "trigger_crash"
//!     inlined_into: 0 <- index reference to "main"
//! }, {
//!     file: "b.c"
//!     line: 13
//!     function: "trigger_crash"
//!     inlined_into: 0 <- index reference to "main"
//! }]
//! ```
//!
//! # Lookups
//!
//! To look up an address `addr` in a SymCache:
//!
//! 1. Find the range covering `addr` via binary search.
//! 2. Find the source location belonging to this range.
//! 3. Return an iterator over a series of source locations that starts at the source location found
//!    in step 2. The iterator climbs up through the inlining hierarchy, ending at the root source
//!    location.
//!
//! The returned source locations contain accessor methods for their function, file, and line
//! number.

#![warn(missing_docs)]

mod error;
mod lookup;
mod raw;
pub mod transform;
mod writer;

use core::panic;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::path::Path;
use std::str;
use symbolic_common::Arch;
use symbolic_common::AsSelf;
use symbolic_common::DebugId;
use symbolic_demangle::Demangle;
use symbolic_demangle::DemangleOptions;
use watto::StringTable;
use watto::{align_to, Pod};

pub use error::{Error, ErrorKind};
pub use lookup::*;
pub use writer::SymCacheConverter;

type Result<T, E = Error> = std::result::Result<T, E>;

/// The latest version of the file format.
///
/// Version history:
///
/// 1: Initial implementation
/// 2: PR #58:  Migrate from UUID to Debug ID
/// 3: PR #148: Consider all PT_LOAD segments in ELF
/// 4: PR #155: Functions with more than 65k line records
/// 5: PR #221: Invalid inlinee nesting leading to wrong stack traces
/// 6: PR #319: Correct line offsets and spacer line records
/// 7: PR #459: A new binary format fundamentally based on addr ranges
/// 8: PR #670: Use LEB128-prefixed string table
pub const SYMCACHE_VERSION: u32 = 8;

/// The serialized SymCache binary format.
///
/// This can be parsed from a binary buffer via [`SymCache::parse`] and lookups on it can be performed
/// via the [`SymCache::lookup`] method.
#[derive(Clone, PartialEq, Eq)]
pub struct SymCache<'data> {
    header: &'data raw::Header,
    files: &'data [raw::File],
    functions: &'data [raw::Function],
    source_locations: &'data [raw::SourceLocation],
    ranges: &'data [raw::Range],
    string_bytes: &'data [u8],
    /// 记录上次遍历到的 source location 位置
    last_range_index: RefCell<usize>,
    /// cabi 调用，持有防止被释放
    /// TODO: String 还可以继续优化为 &str
    pub json_functions: RefCell<Vec<String>>,
    /// 文件路径
    path: String,
}

impl std::fmt::Debug for SymCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymCache")
            .field("version", &self.header.version)
            .field("debug_id", &self.header.debug_id)
            .field("arch", &self.header.arch)
            .field("files", &self.header.num_files)
            .field("functions", &self.header.num_functions)
            .field("source_locations", &self.header.num_source_locations)
            .field("ranges", &self.header.num_ranges)
            .field("string_bytes", &self.header.string_bytes)
            .finish()
    }
}

impl<'data> SymCache<'data> {
    /// Parse the SymCache binary format into a convenient type that allows safe access and
    /// fast lookups.
    pub fn parse(buf: &'data [u8]) -> Result<Self> {
        let (header, rest) = raw::Header::ref_from_prefix(buf).ok_or(ErrorKind::InvalidHeader)?;
        if header.magic == raw::SYMCACHE_MAGIC_FLIPPED {
            return Err(ErrorKind::WrongEndianness.into());
        }
        if header.magic != raw::SYMCACHE_MAGIC {
            return Err(ErrorKind::WrongFormat.into());
        }
        if header.version != SYMCACHE_VERSION && header.version != 7 {
            return Err(ErrorKind::WrongVersion.into());
        }

        let (_, rest) = align_to(rest, 8).ok_or(ErrorKind::InvalidFiles)?;
        let (files, rest) = raw::File::slice_from_prefix(rest, header.num_files as usize)
            .ok_or(ErrorKind::InvalidFiles)?;

        let (_, rest) = align_to(rest, 8).ok_or(ErrorKind::InvalidFunctions)?;
        let (functions, rest) =
            raw::Function::slice_from_prefix(rest, header.num_functions as usize)
                .ok_or(ErrorKind::InvalidFunctions)?;

        let (_, rest) = align_to(rest, 8).ok_or(ErrorKind::InvalidSourceLocations)?;
        let (source_locations, rest) =
            raw::SourceLocation::slice_from_prefix(rest, header.num_source_locations as usize)
                .ok_or(ErrorKind::InvalidSourceLocations)?;

        let (_, rest) = align_to(rest, 8).ok_or(ErrorKind::InvalidRanges)?;
        let (ranges, rest) = raw::Range::slice_from_prefix(rest, header.num_ranges as usize)
            .ok_or(ErrorKind::InvalidRanges)?;

        let (_, rest) = align_to(rest, 8).ok_or(ErrorKind::UnexpectedStringBytes {
            expected: header.string_bytes as usize,
            found: 0,
        })?;
        if rest.len() < header.string_bytes as usize {
            return Err(ErrorKind::UnexpectedStringBytes {
                expected: header.string_bytes as usize,
                found: rest.len(),
            }
            .into());
        }

        Ok(SymCache {
            header,
            files,
            functions,
            source_locations,
            ranges,
            string_bytes: rest,
            last_range_index: RefCell::from(0),
            json_functions: RefCell::from(vec![]),
            path: String::from(""),
        })
    }

    /// 记录 symcache 的 path 用于解析 image name 和 uuid
    pub fn parse_with_path<P: AsRef<Path>>(buf: &'data [u8], path: P) -> Result<Self> {
        match SymCache::parse(buf) {
            Ok(mut symcache) => {
                let path = match path.as_ref().file_stem() {
                    Some(s) => s.to_string_lossy().into_owned(),
                    None => panic!("没有获取到文件路径，文件里面里面保存了 image_name"),
                };
                symcache.path = path;
                Ok(symcache)
            }
            Err(e) => Err(e),
        }
    }

    /// Resolves a string reference to the pointed-to `&str` data.
    fn get_string(&self, offset: u32) -> Option<&'data str> {
        if self.header.version >= 8 {
            // version >= 8: string length prefixes are LEB128
            StringTable::read(self.string_bytes, offset as usize).ok()
        } else {
            // version < 8: string length prefixes are u32
            if offset == u32::MAX {
                return None;
            }
            let len_offset = offset as usize;
            let len_size = std::mem::size_of::<u32>();
            let len = u32::from_ne_bytes(
                self.string_bytes
                    .get(len_offset..len_offset + len_size)?
                    .try_into()
                    .unwrap(),
            ) as usize;

            let start_offset = len_offset + len_size;
            let end_offset = start_offset + len;
            let bytes = self.string_bytes.get(start_offset..end_offset)?;

            std::str::from_utf8(bytes).ok()
        }
    }

    /// The version of the SymCache file format.
    pub fn version(&self) -> u32 {
        self.header.version
    }

    /// Returns true if this symcache's version is the current version of the format.
    pub fn is_latest(&self) -> bool {
        self.header.version == SYMCACHE_VERSION
    }

    /// The architecture of the symbol file.
    pub fn arch(&self) -> Arch {
        self.header.arch
    }

    /// The debug identifier of the cache file.
    pub fn debug_id(&self) -> DebugId {
        self.header.debug_id
    }

    /// image name
    fn image_name(&self) -> String {
        if let Some(s) = StringTable::read(self.string_bytes, 0 as usize).ok() {
            if s.contains("imagename:") {
                s.get(11..).unwrap_or("???").to_owned()
            } else {
                "???".to_owned()
            }
        } else {
            "???".to_owned()
        }
    }

    /// uuid
    pub fn uuid(&self) -> String {
        self.debug_id().to_string().replace("-", "")
    }

    fn source_location_start(&self) -> usize {
        self.header.num_source_locations as usize - self.header.num_ranges as usize
    }
}

impl<'slf, 'd: 'slf> AsSelf<'slf> for SymCache<'d> {
    type Ref = SymCache<'slf>;

    fn as_self(&'slf self) -> &'slf Self::Ref {
        self
    }
}

/// 记录 json 格式的内联函数
#[derive(Serialize, Debug)]
pub(crate) struct JSONInlineFunction {
    /// function name of caller.
    pub(crate) func: String,
    /// file name of caller.
    pub(crate) file: String,
    /// line num of caller invoke.
    pub(crate) line: u32,
}

/// 生成 json 格式的 Function
#[derive(Serialize, Debug)]
pub struct JSONFunction {
    /// function name
    symbol: String,
    /// binary search key, derive from first location's offset.
    start_addr: u32,
    /// end pc
    end_addr: u32,
    /// file anme
    pub(crate) full_file_path: String,
    /// lines mapping info
    pub(crate) line_num: String,
    /// inline functions, expand sequentially if not empty.
    pub(crate) inline: String,
    /// lines mapping info
    #[serde(skip_serializing)]
    pub(crate) line_num_vec: Vec<HashMap<u32, u32>>,
    /// inline functions, expand sequentially if not empty.
    #[serde(skip_serializing)]
    pub(crate) inline_vec: Vec<JSONInlineFunction>,
    /// uuid of current image
    uuid: String,
    /// image name
    image_name: String,
}

impl JSONFunction {
    fn set_end_addr(&mut self, end_addr: u32) {
        self.end_addr = end_addr
    }

    fn push_inline_function(&mut self, inline_function: JSONInlineFunction) {
        self.inline_vec.push(inline_function)
    }

    fn push_source_location(&mut self, source_lcoation: HashMap<u32, u32>) {
        self.line_num_vec.push(source_lcoation)
    }
}

impl<'data> SymCache<'data> {
    fn inline_expansion_enabled(path: &str) -> bool {
        // 过滤 c++ 库的内联展开
        !path.contains("/usr/include/c++/") && !path.contains("usr/bin/../include/c++/")
    }

    fn get_inline_fold_source_location(&self, index: usize) -> &raw::SourceLocation {
        // 内联折叠&聚合内联 caller 的堆栈
        let mut source_location = self
            .source_locations
            .get(index)
            .expect("根据 Range index 没有找到 SourceLocation");
        loop {
            if source_location.inlined_into_idx == u32::MAX {
                break;
            }
            if let Some(inline_file) = self.get_file(source_location.file_idx) {
                if SymCache::inline_expansion_enabled(&inline_file.full_path()) {
                    break;
                }
                source_location = self
                    .source_locations
                    .get(source_location.inlined_into_idx as usize)
                    .expect(&format!(
                        "没有找到内联的 SourceLocation: {}",
                        source_location.inlined_into_idx
                    ));
            } else {
                break;
            }
        }
        return source_location;
    }

    /// Get functions with json format.
    pub fn get_functions(&self, functions_sum: usize, full_path: bool, name_only: bool) {
        if *self.last_range_index.borrow() >= self.ranges.len() - 1 {
            self.json_functions.replace(vec![]);
            return;
        }
        let mut json_functions: Vec<JSONFunction> = vec![];
        let mut last_function_idx = u32::MAX - 1;
        let mut last_file_idx = u32::MAX - 1;
        let mut last_inlined_into_idx: u32 = u32::MAX - 1;
        let skip_num = *self.last_range_index.borrow();
        for (range_index, range) in self.ranges.iter().skip(skip_num).enumerate() {
            let real_range_index = range_index + skip_num;
            let source_location_addr = range.0;
            let source_location = self
                .get_inline_fold_source_location(self.source_location_start() + real_range_index);
            if source_location.function_idx == u32::MAX {
                // 处理最后一个 SourceLocation
                json_functions.push(JSONFunction {
                    symbol: String::from("No match :("),
                    start_addr: source_location_addr,
                    end_addr: u32::MAX,
                    full_file_path: String::new(),
                    line_num_vec: vec![HashMap::from([(
                        source_location_addr,
                        source_location.line,
                    )])],
                    inline_vec: vec![],
                    uuid: self.uuid(),
                    image_name: self.image_name(),
                    line_num: String::new(),
                    inline: String::new(),
                });
                // 处理倒数第二个 function
                let num_json_functions = json_functions.len();
                if !json_functions.is_empty() {
                    if let Some(function) = json_functions.get_mut(num_json_functions - 1) {
                        //  json_functions[n].end_pc = json_functions[n+1].start_pc
                        function.set_end_addr(source_location_addr)
                    }
                }
                self.last_range_index.replace(real_range_index);
                continue;
            }
            // 判断 inlined_into_idx: function_idx 和 file_idx 一致的情况下，内联的 caller 可能不同
            if source_location.function_idx != last_function_idx
                || source_location.file_idx != last_file_idx
                || source_location.inlined_into_idx != last_inlined_into_idx
            {
                // 下面会持有可变引用，len 这里会持有非可变引用，要提前计算好
                let num_json_functions = json_functions.len();
                if !json_functions.is_empty() {
                    if let Some(function) = json_functions.get_mut(num_json_functions - 1) {
                        //  json_functions[n].end_pc = json_functions[n+1].start_pc
                        function.set_end_addr(source_location_addr)
                    }
                }
                if json_functions.len() >= functions_sum {
                    self.last_range_index.replace(real_range_index);
                    break;
                }
                last_function_idx = source_location.function_idx;
                last_file_idx = source_location.file_idx;
                last_inlined_into_idx = source_location.inlined_into_idx;
                let function = match self.get_function(last_function_idx) {
                    Some(function) => function,
                    None => panic!("Function not found for idx: {}", last_function_idx),
                };

                let name_for_demangling = function.name_for_demangling();

                let mut function: JSONFunction = JSONFunction {
                    symbol: function
                        .name_for_demangling()
                        .try_demangle(if name_only {
                            DemangleOptions::name_only()
                        } else {
                            DemangleOptions::complete()
                        })
                        .to_string(),
                    start_addr: source_location_addr,
                    end_addr: u32::MAX,
                    full_file_path: if let Some(file) = self.get_file(source_location.file_idx) {
                        if full_path {
                            file.full_path()
                        } else {
                            file.name()
                        }
                    } else {
                        "".to_owned()
                    },
                    line_num_vec: vec![],
                    inline_vec: vec![],
                    uuid: self.uuid(),
                    image_name: self.image_name(),
                    line_num: String::new(),
                    inline: String::new(),
                };

                if let Some((kn_filepath, kn_symbol)) = name_for_demangling.kotlin_try_demangle() {
                    function.symbol = kn_symbol;
                    function.full_file_path = kn_filepath;
                }

                function.line_num_vec.push(HashMap::from([(
                    source_location_addr,
                    source_location.line,
                )]));
                let mut inlined_into_idx = source_location.inlined_into_idx;
                while inlined_into_idx != u32::MAX {
                    let source_location = self
                        .source_locations
                        .get(inlined_into_idx as usize)
                        .expect("获取内联的 sourcelocation 失败");
                    let inlined_to_function = match self.get_function(source_location.function_idx)
                    {
                        Some(function) => function,
                        None => panic!("Function not found for idx: {}", last_function_idx),
                    };

                    let inline_file = self.get_file(source_location.file_idx);
                    let inline_file = if let Some(file) = inline_file {
                        if full_path {
                            file.full_path()
                        } else {
                            file.name()
                        }
                    } else {
                        "".to_owned()
                    };
                    function.push_inline_function(JSONInlineFunction {
                        func: inlined_to_function
                            .name_for_demangling()
                            .try_demangle(if name_only {
                                DemangleOptions::name_only()
                            } else {
                                DemangleOptions::complete()
                            })
                            .to_string(),
                        file: inline_file,
                        line: source_location.line,
                    });
                    inlined_into_idx = source_location.inlined_into_idx;
                }
                json_functions.push(function);
            } else {
                let num_json_functions = json_functions.len();
                if let Some(function) = json_functions.get_mut(num_json_functions - 1) {
                    function.push_source_location(HashMap::from([(
                        source_location_addr,
                        source_location.line,
                    )]));
                }
            }

            if real_range_index == self.ranges.len() - 1 {
                self.last_range_index.replace(real_range_index);
            }
        }

        let json_functions = json_functions
            .iter_mut()
            .map(|func| {
                func.inline = serde_json::to_string(&func.inline_vec).expect("inline 序列化失败");
                func.line_num =
                    serde_json::to_string(&func.line_num_vec).expect("line_num 序列化失败");
                if let Ok(func_str) = serde_json::to_string(func) {
                    func_str
                } else {
                    panic!("Failed to convert function to string!");
                }
            })
            .collect();
        self.json_functions.replace(json_functions);
    }
}
