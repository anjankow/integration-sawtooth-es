/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

/// from https://github.com/hyperledger/sawtooth-core/blob/v1.2.6/families/smallbank/smallbank_rust/build.rs
extern crate glob;
extern crate protoc_rust;

use protoc_rust::Customize;

// use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=protos/");
    println!("cargo:rerun-if-changed=src/protos/");

    println!("Generating proto files...");
    // let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = "./src"; // output in src/protos directory
    let dest_path = Path::new(&out_dir).join("protos");
    fs::create_dir_all(&dest_path).unwrap();

    let proto_src_files = glob_simple("protos/*.proto");
    println!("{:?}", proto_src_files);

    protoc_rust::Codegen::new()
        .out_dir(&dest_path.to_str().unwrap())
        .inputs(
            &proto_src_files
                .iter()
                .map(|proto_file| proto_file.as_ref())
                .collect::<Vec<&str>>(),
        )
        // directory where .proto files reside
        .includes(&["protos"])
        .customize(Customize::default())
        .run()
        .expect("Error generating rust files from protos");

    // Create mod.rs accordingly
    let mod_file_content = proto_src_files
        .iter()
        .map(|proto_file| {
            let proto_path = Path::new(proto_file);
            format!(
                "pub mod {};",
                proto_path
                    .file_stem()
                    .expect("Unable to extract stem")
                    .to_str()
                    .expect("Unable to extract filename")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut mod_file = File::create(dest_path.join("mod.rs")).unwrap();
    mod_file
        .write_all(mod_file_content.as_bytes())
        .expect("Unable to write mod file");
}

fn glob_simple(pattern: &str) -> Vec<String> {
    glob::glob(pattern)
        .expect("glob")
        .map(|g| {
            g.expect("item")
                .as_path()
                .to_str()
                .expect("utf-8")
                .to_owned()
        })
        .collect()
}
