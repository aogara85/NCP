extern crate csv;
use reqwest::header;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use roxmltree;
use serde_json::Value;
use std::io::Write;
use std::fs::OpenOptions;
use std::path::Path;
use std::thread;
use std::time::Duration;


pub async fn nvd_scanner(filepath:&str) -> Result<(), Box<dyn std::error::Error>>{
    let mut counter = 0;
    let mut result=Vec::<String>::new();
    let mut reader = csv::Reader::from_path(filepath)?;//"./output/cves.csv"
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
    Ok(())
}

pub async fn jvndb_scanner()->Result<(), Box<dyn std::error::Error>>{
    let vulnid = "JVNDB-2021-014971";
    let url = format!("https://jvndb.jvn.jp/myjvn?method=getVulnDetailInfo&feed=hnd&vulnId={}",vulnid);
    let res = reqwest::get(&url).await?.text().await?;
    let doc = roxmltree::Document::parse(&res).unwrap();
    //nodeidのイテレーター
    //elementがあるかないかで分岐。textははじめと終わりのタグ分二個ある。elementのある一つで良い。全てタグ名で管理されている。namespace,attributeには欲しい情報がない
    for id in doc.descendants(){
        if id.is_element(){
            let _result = match id.text(){
                Some(r) => println!("{}:{}",id.tag_name().name(),r),
                None => ()
            };
            //println!("{:?}=={:?}",id.tag_name(),id.text());
        }
        else{
            continue
        }
        //println!("{:?}=={:?}=={:?}=={:?}",id.attributes(),id.namespaces(),id.first_child(),id.first_element_child());
    }
    // let url2 = format!("https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&dateFirstPublishedStartY=2022&dateFirstPublishedStartM=11&dateFirstPublishedStartD=2");
    // let res2 = reqwest::get(&url2).await?.text().await?;
    // let doc2 = roxmltree::Document::parse(&res2).unwrap();
    // println!("{:?}",res2);
    Ok(())
}
//検索ワード参照
//https://docs.github.com/ja/search-github/getting-started-with-searching-on-github/about-searching-on-github
pub  async fn payload_scanner(token:String,query:String)->Result<(), Box<dyn std::error::Error>>{
    let client = reqwest::Client::new();
    let mut headers = header::HeaderMap::new();
    headers.insert("User-Agent","Awesome-Octocat-App".parse()?);
    headers.insert("Accept","application/vnd.github.json".parse()?);
    headers.insert("Authorization",format!("Bearer {}",token).parse()?);
    let search_query = format!("{} exploit OR scanner in:readme created:>2022-11-01",query);
    //let search_query = "cve-2007-6750 AND exploit";
    let url = format!("https://api.github.com/search/repositories?q={}",utf8_percent_encode(&search_query,NON_ALPHANUMERIC));
    let res = client.get(&url).headers(headers).send().await?.text().await?;
    let resj:Value = serde_json::from_str(&res).unwrap();
    println!("{}",resj["total_count"]);
    for result in 0..resj["items"].as_array().unwrap().len(){
        println!("{},{},{}",resj["items"].as_array().unwrap()[result]["full_name"]
        ,resj["items"].as_array().unwrap()[result]["html_url"]
        ,resj["items"].as_array().unwrap()[result]["description"]);
    }

    //search code
    //let search_query = "CVE-2021-20837 AND exploit";
    //let url = format!("https://api.github.com/search/code?q={}",utf8_percent_encode(search_query,NON_ALPHANUMERIC));
    // for result in 0..resj["items"].as_array().unwrap().len(){
    //     println!("score:{} {}:{}",resj["items"].as_array().unwrap()[result]["score"],resj["items"].as_array().unwrap()[result]["repository"]["html_url"],resj["items"].as_array().unwrap()[result]["repository"]["description"]);
    // }
    
    Ok(())
}

fn output_csv(contents:String,filepath:&str) -> Result<(),String>{
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