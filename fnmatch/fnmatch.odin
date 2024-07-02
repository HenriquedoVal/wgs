package fnmatch

import "core:path/filepath"

@export
fnmatch :: proc(a, b : cstring) -> i32 {
    a := string(a)
    b := string(b)
	
    // m: bool = false;
    // err: any;
    
    m, err := filepath.match(a, b)
    res := i32(m)
    // res : i64 = (err << 32) & i32(m)
    
    return res
}
