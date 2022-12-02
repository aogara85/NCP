extern crate walkdir;
use walkdir::WalkDir;
use std::fs;
use std::io;
use std::path::Path;
use std::fs::File;
use std::fs::OpenOptions;
use std::{io::Write};
use std::io::BufReader;
use std::io::BufRead;
use indicatif::{ProgressBar, ProgressStyle};

pub fn file_concatenation(dirpath:&str)-> Result<(), Box<dyn std::error::Error>>{
    let mut filelist :Vec<String> = read_dir(dirpath)?;
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
    //プログレスバーの設定
    let total_size = filelist.len();
    let mut count = 0;
    let pb = ProgressBar::new(total_size.try_into().unwrap());
    pb.set_style(ProgressStyle::with_template("{spinner:.yellow} {elapsed_precise} [{percent:>1}%] {bar:50.green/cyan} {pos:>5}/{len:5} {msg}")
    .unwrap()
    .progress_chars("#>-")); 
    for file in filelist{
        let fp = File::open(file.as_str())?;
        let buffer = BufReader::new(fp);
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
        //プログレスバーのメッセージ処理
        count+=1;
        pb.set_position(count);
        pb.set_message(format!("{} concatenate",file));
        }
        pb.finish_with_message(format!("File consolidation is complete!"));
    Ok(())
}

fn read_dir(dir_path:&str) ->io::Result<Vec<String>>{
    let mut filelist:Vec<String>= Vec::<String>::new();
    for entry in WalkDir::new(dir_path) {
        if entry.as_ref().unwrap().path().is_file(){
            match entry.as_ref().unwrap().path().extension(){
                Some(e) => {
                    if e =="csv"{
                        filelist.push(entry.unwrap().path().to_string_lossy().to_string())
                    }
                    else{
                        continue
                    }
                },
                None =>()
            }
        }
        else{
            continue
        }
    }
    Ok(filelist)
}

pub fn csv_parser(filepath:&str)->Result<(), Box<dyn std::error::Error>>{
    let mut reader = csv::Reader::from_path(filepath)?;
    let mut cves:Vec<String>=Vec::<String>::new();
    output_csv( format!("CVE,Risk,Host,Protocol,Port,Name,Metasploit\n"),"./output/first_report.csv").expect("error");
    output_csv( format!("Host,CVE,Name,See_Also,Descrition\n"),"./output/cve_refernce.csv").expect("error");
    output_csv( format!("CVE\n"),"./output/cves.csv").expect("error");
    output_csv( format!("Host,CVE,Protocol,Port,Name,Descrition\n"),"./output/host_information.csv").expect("error");
    for record in reader.records() {
        let record = record?;
        if &record[3] != "None"{
            output_csv( format!("{},{},{},{},{},{},{}\n",&record[1],&record[3],&record[4],&record[5],&record[6],&record[7],&record[23]),"./output/first_report.csv").expect("error");
        }
        if &record[3] != "None" && &record[1] != ""{
            let des= &record[9]; 
            let cs = &record[11];
            output_csv( format!("{},{},{},{},{}\n",&record[4],&record[1],&record[7],cs.replace("\n",";"),des.replace("\n",";")),"./output/cve_refernce.csv").expect("error");
            cves.push(format!("{}",&record[1]));
        }
        if &record[3] =="None"{
            let des= &record[9];
            output_csv( format!("{},{},{},{},{},{}\n",&record[4],&record[1],&record[5],&record[6],&record[7],des.replace("\n",";")),"./output/host_information.csv").expect("error");
        }
        else{
            continue
        }
    }
    cves.sort();
    cves.dedup();
    for line in cves{
        output_csv( format!("{}\n",line),"./output/cves.csv").expect("error");
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