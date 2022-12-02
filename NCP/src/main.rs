#![allow(non_snake_case)]
extern crate csv;
mod cve_scanner;
use std::fs;
use std::env;
extern crate walkdir;
mod result_extractor;
mod result_csv_parser;

fn show_help(){
    println!("Nessus Auxiliary Tools");
    println!("Usage :");
    println!("      -N                            :  Nessus Auxiliary Functions mode.");
    println!("      -N -t --token                 :  Token mode. Get API token. First of all, Please Nessus log in as a user using option -t to obtain a token.");
    println!("                                    :  A configuration file is created in the current directory.");
    println!("      -N -l --list                  :  List mode. Display the list of nessus scans.");
    println!("      -N -m --multi -f --format     :  Multi Download mode. Multiple files can be downloaded. Specify the folder ID. Check the folder ID with the -l option.");
    println!("      -N -s --single -f --format    :  Single Download mode. Single file can be downloaded. Specify the file ID. Check the file ID with the -l option.");
    println!("                                    :  Select the file format to save from csv or json.");
    println!("");
    println!("      -C directory_path             :  csv files concatenation mode. Concatenate csv files in a directory.");
    println!("      -P file_path                  :  csv parse mode. Specify the path of Summary Nessus csv file.");
    println!("      -S cves_list_file             :  cve scanner mode.");           
}

fn show_example(){
    println!("Example :");
    println!("       NCP.exe -N --single --format json 10");
    println!("       NCP.exe -N -s -f json 10");
    println!("       NCP.exe -N -m -f csv 10");
    println!("       NCP.exe -C ./input");
    println!("       NCP.exe -P ./output/concatenation.csv");
    println!("       NCP.exe -S ./output/cves.csv");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args:Vec<String> = env::args().collect();
    match fs::create_dir("output") {
        Err(_why) => {},
        Ok(_) => {},
    }
    if args.len()<=1{
        show_help();
        show_example();
    }
    else{
        match args[1].as_str(){
            "-N" => {
                match args[2].as_str(){
                    "-t" | "--token" => {
                        result_extractor::create_config().await?;
                    },
                    "-l" | "--list"=> {
                        result_extractor::list_scanid().await?;
                    }
                    "-m" | "--multi"=> {
                        match args[3].as_str(){
                            "-f" | "--format" => {
                                match args[4].as_str(){
                                    "json" => {
                                        result_extractor::download_json(args[5].parse()?,true).await?;
                                    },
                                    "csv" => {
                                        result_extractor::download_csv(args[5].parse()?, true).await?;
                                    }
                                    _ => println!("File formats that can be specified are csv and json.")
                                }
        
                            },
                            _ => println!("Please -f or --format option.")
                        }
                    }
                    "-s" | "--single"=> {
                        match args[3].as_str(){
                            "-f" | "--format" => {
                                match args[4].as_str(){
                                    "json" => {
                                        result_extractor::download_json(args[5].parse()?,false).await?;
                                    },
                                    "csv" => {
                                        result_extractor::download_csv(args[5].parse()?, false).await?;
                                    }
                                    _ => println!("File formats that can be specified are csv and json.")
                                }
        
                            },
                            _ => println!("Please -f or --format option.")
                        }
                    }
                    _ => show_help()
                }
            }
            "-C" => {
                result_csv_parser::file_concatenation(args[2].as_str()).expect("Usage -C Directory_path");
            },
            "-P" => {
                result_csv_parser::csv_parser(args[2].as_str())?;
            },
            "-S" =>{
                cve_scanner::nvd_scanner(args[2].as_str()).await?;
            },
            "-s" =>{
                cve_scanner::jvndb_scanner().await?;
            },
            "-e" =>{
                cve_scanner::payload_scanner(args[2].to_string(),args[3].to_string()).await.expect("error");
            },
            _ => show_help()
        }
    }
    Ok(())
}
