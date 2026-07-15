fn main() {
	println!("Testing CPU limit");
	let mut x: u64 = 0;

	loop {
		x = x.wrapping_add(1);
		if x % 1_000_000_000 == 0 {
			println!("{}",x);
		}
	}
}
