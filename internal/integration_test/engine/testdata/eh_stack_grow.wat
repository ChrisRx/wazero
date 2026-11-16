;; A try_table whose body grows the stack (deep recursion, with callees
;; entering and leaving their own try_tables on the way) before throwing to
;; it. The handler must resume in the moved stack with the entering frame's
;; locals and the exception's value.
(module
  (tag $e (param i32))

  ;; Enters and leaves a try_table of its own, so leaving happens in place.
  (func $inner_try (param $n i32) (result i32)
    (block $caught (result i32)
      (try_table (result i32) (catch $e $caught)
        (i32.add (local.get $n) (i32.const 1)))))

  ;; Recurses $n times, with a few locals to make frames bigger, then throws
  ;; $n + 42 from the bottom.
  (func $deep (param $n i32) (param $v i32)
    (local $a i64) (local $b i64) (local $c f64)
    (local.set $a (i64.extend_i32_u (local.get $n)))
    (local.set $b (i64.mul (local.get $a) (i64.const 3)))
    (local.set $c (f64.convert_i64_u (local.get $b)))
    (if (i32.eqz (local.get $n))
      (then (throw $e (i32.add (local.get $v) (i32.const 42)))))
    (drop (call $inner_try (local.get $n)))
    (call $deep (i32.sub (local.get $n) (i32.const 1)) (local.get $v))
    ;; Keep the locals alive across the call.
    (drop (local.get $a)) (drop (local.get $b)) (drop (local.get $c)))

  ;; Returns the thrown value plus locals set before and inside the body.
  (func (export "run") (param $depth i32) (result i32)
    (local $before i32) (local $inside i32)
    (local.set $before (i32.const 1000))
    (block $caught (result i32)
      (try_table (catch $e $caught)
        (local.set $inside (i32.const 20000))
        (call $deep (local.get $depth) (i32.const 0)))
      (return (i32.const -1)))
    (i32.add (local.get $before))
    (i32.add (local.get $inside))))
