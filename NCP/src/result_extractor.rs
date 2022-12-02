#[macro_use] use prettytable;
use prettytable::{table, row};
use std::{io, fs};
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use std::fs::File;
use std::io::Read;
use reqwest::ClientBuilder;
use std::path::Path;
use std::fs::OpenOptions;
use std::{io::Write};


pub async fn get_token() -> Result<String, Box<dyn std::error::Error>>{
    println!("username:");
    let mut username = String::new();
    std::io::stdin().read_line(&mut username).ok();
    println!("password:");
    let mut password = String::new();
    std::io::stdin().read_line(&mut password).ok();
    let credential = json!({
        "username":username.trim(),
        "password":password.trim()
    });
    let get_token_url ="https://localhost:8834/session";
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let res = client.post(get_token_url).json(&credential).send().await?;
    let body = res.text().await?;
    let resj:Value = serde_json::from_str(&body).unwrap();
    Ok(resj["token"].as_str().unwrap().to_owned())//strにして参照先を返す
}

pub async fn create_config() -> Result<(), Box<dyn std::error::Error>>{
    let token = get_token().await?;
    println!("accesskey:");
    let mut accesskey = String::new();
    std::io::stdin().read_line(&mut accesskey).ok();
    println!("secretkey:");
    let mut secretkey = String::new();
    std::io::stdin().read_line(&mut secretkey).ok();
    let config = json!({
        "X-Cookie": format!("{}",token),
        "X-ApiKeys": format!("accessKey={};secretKey={}",accesskey.trim(),secretkey.trim())
    });
    output_file("./config", config.to_string())?;
    Ok(())
}

pub async fn list_scanid() -> Result<(), Box<dyn std::error::Error>>{
    let mut file = File::open("./config")?;
    let mut buffer = String::new();
    let _ = file.read_to_string(&mut buffer)?;
    let readj:Value = serde_json::from_str(&buffer)?;
    let mut headers = HeaderMap::new();
    headers.insert("X-Cookie",readj["X-Cookie"].as_str().unwrap().parse()?);
    headers.insert("X-ApiKeys",readj["X-ApiKeys"].as_str().unwrap().parse()?);
    let url = "https://localhost:8834/scans";
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let res = client.get(url).headers(headers).send().await?;
    let body = res.text().await?;
    let resj:Value = serde_json::from_str(&body).unwrap();
    let mut table = table!(["name","folder_id","scan_id"]);
    for i in resj["scans"].as_array(){
        for j in i{
            table.add_row(row![j["name"],j["folder_id"],j["id"]]);
        }
    }
    table.printstd();
    Ok(())
}
pub async fn read_credential() -> Result<HeaderMap, Box<dyn std::error::Error>>{
    let mut file = File::open("./config")?;
    let mut buffer = String::new();
    let _ = file.read_to_string(&mut buffer)?;
    let readj:Value = serde_json::from_str(&buffer)?;
    let mut headers = HeaderMap::new();
    headers.insert("X-Cookie",readj["X-Cookie"].as_str().unwrap().parse()?);
    headers.insert("X-ApiKeys",readj["X-ApiKeys"].as_str().unwrap().parse()?);
    Ok(headers)
}
pub async fn download_json(id:u32,folder:bool) -> Result<(), Box<dyn std::error::Error>>{
    if folder{
        let headers = read_credential().await?;
        let url = "https://localhost:8834/scans";
        let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
        let res = client.get(url).headers(headers).send().await?;
        let body = res.text().await?;
        let resj:Value = serde_json::from_str(&body).unwrap();
        for i in resj["scans"].as_array(){
            for j in i{
                if j["folder_id"] == id{
                    fs::create_dir_all(format!("./output/{}",j["folder_id"]))?;
                    let headers_scan = read_credential().await?;
                    let url_scan = format!("https://localhost:8834/scans/{}",j["id"]);
                    let client_scan = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
                    let res_scan = client_scan.get(url_scan).headers(headers_scan).send().await?;
                    let body_scan = res_scan.text().await?;
                    let resj_scan:Value = serde_json::from_str(&body_scan).unwrap();
                    output_file(format!("./output/{}/{}_{}.json",j["folder_id"],id,j["id"]).as_str(), resj_scan.to_string())?;
                    println!("Success download ./output/{}/{}_{}.json",j["folder_id"],id,j["id"])
                }
                else{
                    continue
                }
            }
        }
    }
    else {
        let headers_file = read_credential().await?;
        let url_file = format!("https://localhost:8834/scans/{}",id);
        let client_file = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
        let res_file = client_file.get(url_file).headers(headers_file).send().await?;
        let body_file = res_file.text().await?;
        let resj_file:Value = serde_json::from_str(&body_file).unwrap();
        output_file(format!("./output/{}.json",id,).as_str(), resj_file.to_string())?;
    }

    Ok(())
}

async fn get_file_id_csv(scan_id:u32) -> Result<u64, Box<dyn std::error::Error>>{
    let url = format!("https://localhost:8834/scans/{}/export",scan_id);
    let headers = read_credential().await?;
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let data = json!({
        "format":"csv",
        "template_id":true
    });
    let res = client.post(url).headers(headers).json(&data).send().await?;
    let body = res.text().await?;
    let resj:Value = serde_json::from_str(&body).unwrap();
    Ok((resj["file"]).as_u64().unwrap().to_owned())
}
async fn check_download_status(id:u32,file_id:u64) -> Result<String, Box<dyn std::error::Error>>{
    let url = format!("https://localhost:8834/scans/{}/export/{}/status",id,file_id);
    let headers = read_credential().await?;
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let res = client.get(url).headers(headers).send().await?;
    let body = res.text().await?;
    let resj:Value = serde_json::from_str(&body).unwrap();
    Ok(resj["status"].as_str().unwrap().to_owned())
}

pub async fn download_csv(id:u32,folder:bool) -> Result<(), Box<dyn std::error::Error>>{
    if folder{
        let headers = read_credential().await?;
        let url = "https://localhost:8834/scans";
        let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
        let res = client.get(url).headers(headers).send().await?;
        let body = res.text().await?;
        let resj:Value = serde_json::from_str(&body).unwrap();
        for i in resj["scans"].as_array(){
            for j in i{
                if j["folder_id"] == id{
                    fs::create_dir_all(format!("./output/{}",j["folder_id"]))?;
                    let file_id:u64 =get_file_id_csv(j["id"].as_u64().unwrap().try_into().unwrap()).await?;
                    while check_download_status(j["id"].as_u64().unwrap().try_into().unwrap(), file_id).await? != "ready"{
                    }
                    let url = format!("https://localhost:8834/scans/{}/export/{}/download",j["id"],file_id);
                    let headers = read_credential().await?;
                    let client_file = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
                    let res_file = client_file.get(url).headers(headers).send().await?;
                    let body_file = res_file.bytes().await?;
                    let mut out = File::create(format!("./output/{}/result_{}_{}.csv",j["folder_id"],id,j["id"]))?;
                    io::copy(&mut body_file.as_ref(), &mut out)?;
                    println!("Succsess download ./output/{}/result_{}_{}.csv",j["folder_id"],id,j["id"])
                }
                else{
                    continue
                }
            }
        }

    }
    else{
        let file_id:u64 = get_file_id_csv(id).await?;
        while check_download_status(id, file_id).await? != "ready"{
        }
        let url = format!("https://localhost:8834/scans/{}/export/{}/download",id,file_id);
        let headers = read_credential().await?;
        let client_file = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
        let res_file = client_file.get(url).headers(headers).send().await?;
        let body_file = res_file.bytes().await?;
        let mut out = File::create(format!("./output/result_{}.csv",id))?;
        io::copy(&mut body_file.as_ref(), &mut out)?;
    }
    Ok(())
}

pub fn output_file(filename:&str,contents:String) -> Result<(),String>{
    let outpath:&Path=Path::new(filename);
    let mut outfile = match OpenOptions::new()
   .create(true)
   .write(true)
   .open(outpath)    {
       Err(why) => panic!("Couldn't open {}: {}", "file", why),
       Ok(file) => file,
   };
   match outfile.write_all(contents.as_bytes()) {
    Ok(_r) => {}, Err(_why) => return Err(format!("Could not to write file: {}", outpath.display()))
}
    Ok(())
}