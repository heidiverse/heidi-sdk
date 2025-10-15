/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.   
 */

//! Provide logging facilities for iOS and Android using the options
//! available for the respective platform.
//! 
//! For iOS this means we just use println to print to stdout. On Android
//! we use [__android_log_write] to print to logcat.

#[cfg(target_os = "android")]
use libc::{c_char, c_int};
#[cfg(target_os = "android")]
use std::ffi::CString;

pub const LOG_TAG_FIDO_CLIENT: &str = "Rust_FidoClient";

#[repr(C)]
pub enum LogPriority {
    UNKNOWN = 0,
    DEFAULT,
    VERBOSE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL,
    SILENT,
}

#[macro_export]
macro_rules! log_warn {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::WARN, $tag, $msg);
    };
}

#[macro_export]
macro_rules! log_error {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::ERROR, $tag, $msg);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::DEBUG, $tag, $msg);
    };
}

#[cfg(not(target_os = "android"))]
pub fn log(prio: LogPriority, tag: &str, text: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let msg = format!("[{}] {}", tag, text);
    match prio {
        LogPriority::DEBUG => {
            println!("{}", msg);
        }
        LogPriority::WARN => {
            println!("{}", msg);
        }
        LogPriority::ERROR => {
            println!("{}", msg);
        }
        _ => {
            println!("[{}] {}", tag, text);
        }
    }
}

#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

/// Writes a log message [text] with the given [prio]rity and [tag] to Android's logcat.
#[cfg(target_os = "android")]
pub fn log(prio: LogPriority, tag: &str, text: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let tag = CString::new(tag).unwrap();
    let text = CString::new(text).unwrap();

    unsafe {
        __android_log_write(prio as c_int, tag.as_ptr(), text.as_ptr());
    }
}
