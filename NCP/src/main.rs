#![allow(non_snake_case)]
extern crate csv;
use std::fs;
use std::io;
use std::path::Path;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::{io::Write};
use std::io::BufReader;
use std::io::BufRead;

/*
struct Record {
    pluginid:String,
    CVE:String
    cvss2score:String,
    risk:String,
    host:String,
    protocol:String,
    port:String,
    name:String,
    synopsis:String,
    description:String,
    solution:String,
    see_also:String,
    plugin_output:String,
    stig_severity:String,
    cvss3_base_score:String,
    cvss2_temporal_score:String,
    cvss3_temporal_score:String,
    risk_factor:String,
    bid:String,
    xref:String,
    mskb:String,
    plugin_publication_date:String,
    plugin_modification_date:String,
    metasploit:String,
    core_impact:String,
    canvas:String
}
*/

fn read_dir<P: AsRef<Path>>(dir_path: P) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(dir_path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_file() {
                match entry.path().extension(){
                    Some(t)=>t,
                    None=>panic!("Contains files with only an extension but no name")
                };
                if entry.path().extension().unwrap() == "csv"{
                    Some(entry.path().to_string_lossy().into_owned())
                }
                else{
                    None
                }
            } else {
                None
            }
        })
        .collect())
}

// fn file_concatenation()-> Result<(), Box<dyn std::error::Error>>{
//     let args:Vec<String> = env::args().collect();
//     for filelist in read_dir(args[2].as_str()).unwrap(){
//         println!("{}",filelist);
//         let mut file = File::open(filelist.as_str())?;
//         let mut buffer = String::new();
//         file.read_to_string(&mut buffer).expect("read error");
//         let outpath:&Path=Path::new("./output.csv");
//         let mut outfile = match OpenOptions::new()
//        .create(true)
//        .write(true)
//        .append(true)
//        .open(outpath)    {
//            Err(why) => panic!("Couldn't open {}: {}", "file", why),
//            Ok(file) => file,
//        };
//        match outfile.write_all(buffer.as_bytes()) {
//         Ok(_r) => {}, Err(_why) => println!("error")
//     }
//      }

//     Ok(())
// }

fn file_concatenation()-> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    if args[2].as_str()=="-d" || args[2].as_str()=="--directory"{
        let mut filelist :Vec<String> = read_dir(args[3].as_str())?;
        let mut counter = 0;
        for file in &filelist{
            println!("{} | {}",counter,file);
            counter +=1
        }
        println!("--------------------------------------------");
        println!("Specify the first column of the output csv.");
        println!("Please type number:");
        let mut type_number =String::new();
        std::io::stdin().read_line(&mut type_number)?;
        let target:u8 = type_number.trim().parse().unwrap();
        fs::copy(&filelist[target as usize],"./output/concatenation.csv").expect("file cannot create");
        filelist.remove(target as usize); 
        for file in filelist{
            let file = File::open(file.as_str())?;
            let buffer = BufReader::new(file);
            for (num,line) in buffer.lines().enumerate(){
                if num !=0{
                    let outpath:&Path=Path::new("./output/concatenation.csv");
                    let mut outfile = match OpenOptions::new()
                   .create(true)
                   .write(true)
                   .append(true)
                   .open(outpath)    {
                       Err(why) => panic!("Couldn't open {}: {}", "file", why),
                       Ok(file) => file,
                   };
                   let _ = writeln!(outfile,"{}",line?);
                }
                else{
                    continue
                }
            }
    
         }
    }
    else{
        println!("Csv Concatenation mode Usage:");
        println!("-d    --directory      Specify the directory path of Nessus csv reports")        
    }

    Ok(())
}

fn csv_parser()->Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    if args[2].as_str()=="-f" || args[2].as_str()=="--file"{
        let mut reader = csv::Reader::from_path(args[3].as_str())?;
        output_csv( format!("CVE,Risk,Host,Protocol,Port,Name,Metasploit\n"),"./output/first_report.csv").expect("error");
        output_csv( format!("Host,CVE,Name,See_Also,Descrition\n"),"./output/cve_refernce.csv").expect("error");
        output_csv( format!("Host,Descrition\n"),"./output/host_information.csv").expect("error");
        for record in reader.records() {
            let record = record?;
            if &record[3] != "None"{
                output_csv( format!("{},{},{},{},{},{},{}\n",&record[1],&record[3],&record[4],&record[5],&record[6],&record[7],&record[23]),"./output/first_report.csv").expect("error");
            }
            if &record[3] != "None" && &record[1] != ""{
                let des= &record[9]; 
                let cs = &record[11];
                output_csv( format!("{},{},{},{},{}\n",&record[4],&record[1],&record[7],cs.replace("\n",";"),des.replace("\n",";")),"./output/cve_refernce.csv").expect("error");
            }
            if &record[3] =="None"{
                let des= &record[9];
                output_csv( format!("{},{}\n",&record[4],des.replace("\n",";")),"./output/host_information.csv").expect("error");
            }
            else{
                continue
            }
        }
    }
    else{
        println!("Csv Parser Usage:");
        println!("-f    --file      Specify the path of Summary Nessus csv file")
    }
    Ok(())
}

pub fn output_csv(contents:String,filepath:&str) -> Result<(),String>{
    let outpath:&Path=Path::new(&filepath);
    let mut outfile = match OpenOptions::new()
   .create(true)
   .write(true)
   .append(true)
   .open(outpath)    {
       Err(why) => panic!("Couldn't open {}: {}", "file", why),
       Ok(file) => file,
   };
   match outfile.write_all(contents.as_bytes()) {
    Ok(_r) => {}, Err(_why) => return Err(format!("Could not to write file: {}", outpath.display()))
}
    Ok(())
}

fn main() {
    let args:Vec<String> = env::args().collect();
    match fs::create_dir("output") {
        Err(_why) => {},
        Ok(_) => {},
    }
    if args.len()<=1{
        println!("Usage :");
        println!("-C        csv files concatenation mode");
        println!("-P        csv parse mode");
        
    }
    else{
        match args[1].as_str(){
            "-C" => {
                file_concatenation().expect("Usage:-C -d directory");
            },
            "-P" => {
                csv_parser().expect("Usage -P -f csv file");
            },
            _ =>()
        }
    }
}
