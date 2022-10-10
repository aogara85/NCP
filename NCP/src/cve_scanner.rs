extern crate csv;
use serde_json::Value;
use std::env;
use std::io::Write;
use std::fs::OpenOptions;
use std::path::Path;
use std::thread;
use std::time::Duration;


pub async fn nvd_scanner() -> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    let mut counter = 0;
    if args[2].as_str()=="-l" || args[2].as_str()=="--list"{
        let mut result=Vec::<String>::new();
        let mut reader = csv::Reader::from_path(args[3].as_str())?;//"./output/cves.csv"

        for record in reader.records() {
            let record = record?;
            let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",&record[0]);
            let res = reqwest::get(&url).await?.text().await?;
            let resj:Value = serde_json::from_str(&res).unwrap();
            result.push(format!("{},{}",&record[0],resj["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]));
            counter +=1;
            if counter % 5 ==0{
                thread::sleep(Duration::from_millis(30000));
            }
        }
        output_csv( format!("CVE,nvd_Description\n"),"./output/nvd_result.csv").expect("error");
        for line in result{
            output_csv(format!("{}\n",line), "./output/nvd_result.csv")?;
        }

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