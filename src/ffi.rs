// SPDX-License-Identifier: MIT OR Apache-2.0 OR Zlib

// Copyright 2023 John Nunley
//
// Licensed under the Apache License, Version 2.0, the MIT License, and
// the Zlib license. You may not use this software except in compliance
// with at least one of these licenses. You should have received a copy
// of these licenses with this software. You may also find them at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//     https://opensource.org/licenses/MIT
//     https://opensource.org/licenses/Zlib
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the licenses for the specific language governing permissions and
// limitations under the licenses.

//! FFI bindings to Xlib and XlibXCB.

use as_raw_xcb_connection::xcb_connection_t;
use std::os::raw::{c_char, c_int, c_uchar, c_ulong};

/// Base type for the display pointer.
pub(crate) enum Display {}

/// The type of the error.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct XErrorEvent {
    pub type_: c_int,
    pub display: *mut Display,
    pub resourceid: c_ulong,
    pub serial: c_ulong,
    pub error_code: c_uchar,
    pub request_code: c_uchar,
    pub minor_code: c_uchar,
}

// Function pointer types.
type XOpenDisplay = unsafe extern "C" fn(display_name: *const c_char) -> *mut Display;
type XCloseDisplay = unsafe extern "C" fn(display: *mut Display) -> c_int;
type XGetXCBConnection = unsafe extern "C" fn(display: *mut Display) -> *mut xcb_connection_t;
pub(crate) type XErrorHook =
    Option<unsafe extern "C" fn(display: *mut Display, error_event: *mut XErrorEvent) -> c_int>;
type XSetErrorHandler = unsafe extern "C" fn(handler: XErrorHook) -> XErrorHook;
type XInitThreads = unsafe extern "C" fn() -> c_int;

/// Catalogue of functions offered by Xlib.
pub(crate) struct Xlib {
    /// The currently loaded Xlib library.
    #[cfg(feature = "dlopen")]
    _xlib_library: libloading::Library,

    /// The currently loaded XlibXcb library.
    #[cfg(feature = "dlopen")]
    _xlib_xcb_library: libloading::Library,

    /// The XOpenDisplay function.
    x_open_display: XOpenDisplay,

    /// The XCloseDisplay function.
    x_close_display: XCloseDisplay,

    /// The XGetXCBConnection function.
    x_get_xcb_connection: XGetXCBConnection,

    /// The XSetErrorHandler function.
    x_set_error_handler: XSetErrorHandler,

    /// The XInitThreads function.
    x_init_threads: XInitThreads,
}

impl Xlib {
    /// Open a new connection to the X server.
    pub(crate) unsafe fn open_display(&self, display_name: *const c_char) -> *mut Display {
        (self.x_open_display)(display_name)
    }

    /// Close a connection to the X server.
    pub(crate) unsafe fn close_display(&self, display: *mut Display) -> c_int {
        (self.x_close_display)(display)
    }

    /// Get the XCB connection from an Xlib display.
    pub(crate) unsafe fn get_xcb_connection(&self, display: *mut Display) -> *mut xcb_connection_t {
        (self.x_get_xcb_connection)(display)
    }

    /// Set the error handler.
    pub(crate) unsafe fn set_error_handler(&self, handler: XErrorHook) -> XErrorHook {
        (self.x_set_error_handler)(handler)
    }

    /// Initialize threads.
    pub(crate) unsafe fn init_threads(&self) -> c_int {
        (self.x_init_threads)()
    }

    /// Load the Xlib library at runtime.
    #[cfg_attr(coverage, no_coverage)]
    #[cfg(not(feature = "dlopen"))]
    pub(crate) fn load() -> Result<Self, std::io::Error> {
        #[link(name = "X11", kind = "dylib")]
        extern "C" {
            fn XOpenDisplay(display_name: *const c_char) -> *mut Display;
            fn XCloseDisplay(display: *mut Display) -> c_int;
            fn XSetErrorHandler(handler: XErrorHook) -> XErrorHook;
            fn XInitThreads() -> c_int;
        }

        #[link(name = "X11-xcb", kind = "dylib")]
        extern "C" {
            fn XGetXCBConnection(display: *mut Display) -> *mut xcb_connection_t;
        }

        Ok(Self {
            x_open_display: XOpenDisplay,
            x_close_display: XCloseDisplay,
            x_get_xcb_connection: XGetXCBConnection,
            x_set_error_handler: XSetErrorHandler,
            x_init_threads: XInitThreads,
        })
    }

    /// Load the Xlib library at runtime.
    #[cfg_attr(coverage, no_coverage)]
    #[cfg(feature = "dlopen")]
    pub(crate) fn load() -> Result<Self, libloading::Error> {
        let xlib_library = unsafe { libloading::Library::new("libX11.so") }?;
        let xlib_xcb_library = unsafe { libloading::Library::new("libX11-xcb.so") }?;

        let x_open_display = unsafe { xlib_library.get::<XOpenDisplay>(b"XOpenDisplay\0")? };

        let x_close_display = unsafe { xlib_library.get::<XCloseDisplay>(b"XCloseDisplay\0")? };

        let x_set_error_handler =
            unsafe { xlib_library.get::<XSetErrorHandler>(b"XSetErrorHandler\0")? };

        let x_get_xcb_connection =
            unsafe { xlib_xcb_library.get::<XGetXCBConnection>(b"XGetXCBConnection\0")? };

        let x_init_threads = unsafe { xlib_library.get::<XInitThreads>(b"XInitThreads\0")? };

        Ok(Self {
            x_open_display: *x_open_display,
            x_close_display: *x_close_display,
            x_get_xcb_connection: *x_get_xcb_connection,
            x_set_error_handler: *x_set_error_handler,
            x_init_threads: *x_init_threads,
            _xlib_library: xlib_library,
            _xlib_xcb_library: xlib_xcb_library,
        })
    }
}
