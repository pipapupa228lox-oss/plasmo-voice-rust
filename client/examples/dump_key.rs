fn main() {
    let id = pv_client::identity::Identity::generate().unwrap();
    let der = id.public_key();
    println!("// {} bytes", der.len());
    print!("const PUBLIC_KEY: [u8; {}] = [", der.len());
    for (i, b) in der.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("{b}, ");
    }
    println!("\n];");
}
