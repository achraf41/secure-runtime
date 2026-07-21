fn main() {
    for (index, argument) in std::env::args().skip(1).enumerate() {
        println!("arg[{index}] = {argument}");
    }
}
