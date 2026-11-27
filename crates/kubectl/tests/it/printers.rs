//! Ports of client-go `util/jsonpath/jsonpath_test.go` (TestTypesInput,
//! TestJSONInput, TestKubernetes, TestEmptyRange, TestNestedRanges,
//! TestFilterPartialMatchesSometimesMissingAnnotations) for the executor.

mod jsonpath {
    use kubernetes_rs_kubectl::printers::jsonpath::JsonPath;
    use serde_json::{json, Value};

    fn run(template: &str, input: &Value, allow_missing: bool) -> Result<String, String> {
        let mut j = JsonPath::new("test").allow_missing_keys(allow_missing);
        j.parse(template)?;
        j.execute(input)
    }

    fn check(template: &str, input: &Value, expect: &str) {
        assert_eq!(
            run(template, input, false).as_deref(),
            Ok(expect),
            "{template}"
        );
    }

    fn sorted_fields(s: &str) -> Vec<String> {
        let mut v: Vec<String> = s.split_whitespace().map(String::from).collect();
        v.sort();
        v
    }

    #[test]
    fn types_input() {
        let t = json!({
            "bools": [true, false, true, false],
            "integers": [1, 2, 3, 4],
            "floats": [1.0, 2.2, 3.3, 4.0],
            "strings": ["one", "two", "three", "four"],
            "interfaces": [true, "one", 1, 1.1],
            "maps": [
                {"name": "one", "value": 1}, {"name": "two", "value": 2.02},
                {"name": "three", "value": 3.03}, {"name": "four", "value": 4.04}],
        });
        check("{ .bools }", &t, "[true,false,true,false]");
        check("{ .bools[0] }", &t, "true");
        check("{ .bools[-1] }", &t, "false");
        check("{ .bools[0:2] }", &t, "true false");
        check("{ .bools[:2] }", &t, "true false");
        check("{ .bools[:4:2] }", &t, "true true");
        check("{ .integers }", &t, "[1,2,3,4]");
        check("{ .integers[-2] }", &t, "3");
        check("{ .integers[:4:2] }", &t, "1 3");
        check("{ .floats }", &t, "[1,2.2,3.3,4]");
        check("{ .floats[0] }", &t, "1");
        check("{ .floats[:4:2] }", &t, "1 3.3");
        check("{ .strings }", &t, r#"["one","two","three","four"]"#);
        check("{ .strings[-2] }", &t, "three");
        check("{ .strings[:4:2] }", &t, "one three");
        check("{ .interfaces }", &t, r#"[true,"one",1,1.1]"#);
        check("{ .interfaces[:4:2] }", &t, "true 1");
        check("{ .maps[0] }", &t, r#"{"name":"one","value":1}"#);
        check(
            "{ .maps[0:2] }",
            &t,
            r#"{"name":"one","value":1} {"name":"two","value":2.02}"#,
        );
        check(
            "{ .maps[::2] }",
            &t,
            r#"{"name":"one","value":1} {"name":"three","value":3.03}"#,
        );
        check(
            "{ .maps[1::2] }",
            &t,
            r#"{"name":"two","value":2.02} {"name":"four","value":4.04}"#,
        );
    }

    #[test]
    fn json_input() {
        let points = json!([
            {"id": "i1", "x": 4, "y": -5},
            {"id": "i2", "x": -2, "y": -5, "z": 1},
            {"id": "i3", "x": 8, "y": 3},
            {"id": "i4", "x": -6, "y": -1},
            {"id": "i5", "x": 0, "y": 2, "z": 1},
            {"id": "i6", "x": 1, "y": 4},
            {"id": "i7", "x": null, "y": 4}
        ]);
        check("{[?(@.z)].id}", &points, "i2 i5");
        check("{[0]['id']}", &points, "i1");
        check("{[-1]['x']}", &points, "null");
        // A null operand is "invalid type for comparison" (funcs.go basicKind).
        assert_eq!(
            run("{[?(@.x>0)].id}", &points, false),
            Err("invalid type for comparison".to_string())
        );
        check("{[?(@.y>2)].id}", &points, "i3 i6 i7");
    }

    fn nodes() -> Value {
        json!({
          "kind": "List",
          "items": [
            {"kind": "None",
             "metadata": {"name": "127.0.0.1", "labels": {"kubernetes.io/hostname": "127.0.0.1"}},
             "status": {"capacity": {"cpu": "4"}, "ready": true,
                        "addresses": [{"type": "LegacyHostIP", "address": "127.0.0.1"}]}},
            {"kind": "None",
             "metadata": {"name": "127.0.0.2", "labels": {"kubernetes.io/hostname": "127.0.0.2"}},
             "status": {"capacity": {"cpu": "8"}, "ready": false,
                        "addresses": [{"type": "LegacyHostIP", "address": "127.0.0.2"},
                                      {"type": "another", "address": "127.0.0.3"}]}}
          ],
          "users": [
            {"name": "myself", "user": {}},
            {"name": "e2e", "user": {"username": "admin", "password": "secret"}}
          ]
        })
    }

    #[test]
    fn kubernetes() {
        let n = nodes();
        check(
            "{range .items[*]}{.metadata.name}, {end}{.kind}",
            &n,
            "127.0.0.1, 127.0.0.2, List",
        );
        check(
            r#"{range .items[*]}{.metadata.name}{"\t"}{end}"#,
            &n,
            "127.0.0.1\t127.0.0.2\t",
        );
        check(
            "{.items[*].status.addresses[*].address}",
            &n,
            "127.0.0.1 127.0.0.2 127.0.0.3",
        );
        check(
            "{range .items[*]}{range .status.addresses[*]}{.address}, {end}{end}",
            &n,
            "127.0.0.1, 127.0.0.2, 127.0.0.3, ",
        );
        check("{.items[*].metadata.name}", &n, "127.0.0.1 127.0.0.2");
        check(
            "{.items[*]['metadata.name', 'status.capacity']}",
            &n,
            r#"127.0.0.1 127.0.0.2 {"cpu":"4"} {"cpu":"8"}"#,
        );
        check(
            "{range .items[*]}[{.metadata.name}, {.status.capacity}] {end}",
            &n,
            r#"[127.0.0.1, {"cpu":"4"}] [127.0.0.2, {"cpu":"8"}] "#,
        );
        check(r#"{.users[?(@.name=="e2e")].user.password}"#, &n, "secret");
        check(
            r"{.items[0].metadata.labels.kubernetes\.io/hostname}",
            &n,
            "127.0.0.1",
        );
        check(
            r#"{.items[?(@.metadata.labels.kubernetes\.io/hostname=="127.0.0.1")].kind}"#,
            &n,
            "None",
        );
        check("{.items[?(@..ready==true)].metadata.name}", &n, "127.0.0.1");
        let out = run("{..name}", &n, false).unwrap();
        assert_eq!(
            sorted_fields(&out),
            sorted_fields("127.0.0.1 127.0.0.2 myself e2e")
        );
    }

    #[test]
    fn empty_range() {
        let empty = json!({"items": []});
        assert_eq!(
            run("{range .items[*]}{.metadata.name}{end}", &empty, true).as_deref(),
            Ok("")
        );
        assert_eq!(
            run(
                r#"{range .items[*]}{.metadata.name}{":"}{range @.spec.containers[*]}{.name}{","}{end}{"+"}{end}"#,
                &empty,
                true
            )
            .as_deref(),
            Ok("")
        );
    }

    #[test]
    fn nested_ranges() {
        let c = |names: &[&str]| -> Value {
            json!(names
                .iter()
                .map(|n| json!({
                    "name": n, "another": [{"name": "value1"}, {"name": "value2"}]
                }))
                .collect::<Vec<_>>())
        };
        let data = json!({"items": [
            {"metadata": {"name": "pod1"}, "spec": {"containers": c(&["foo", "bar"])}},
            {"metadata": {"name": "pod2"}, "spec": {"containers": c(&["baz"])}},
        ]});
        check(
            r#"{range .items[*]}{.metadata.name}{":"}{range @.spec.containers[*]}{.name}{","}{end}{"+"}{end}"#,
            &data,
            "pod1:foo,bar,+pod2:baz,+",
        );
        check(
            concat!(
                r#"{range .items[*]}{.metadata.name}{"~"}{range @.spec.containers[*]}{.name}{":"}"#,
                r##"{range @.another[*]}{.name}{","}{end}{"+"}{end}{"#"}{end}"##
            ),
            &data,
            "pod1~foo:value1,value2,+bar:value1,value2,+#pod2~baz:value1,value2,+#",
        );
        check(
            concat!(
                r#"{range .items[*]}{.metadata.name}{"\t"}{range @.spec.containers[*]}{.name}{" "}{end}"#,
                r#"{"\t"}{range @.spec.containers[*]}{.name}{" "}{end}{"\n"}{end}"#
            ),
            &data,
            "pod1\tfoo bar \tfoo bar \npod2\tbaz \tbaz \n",
        );
    }

    #[test]
    fn filter_partial_matches_with_missing_annotations() {
        let data = json!({"items": [
            {"metadata": {"name": "pod1", "annotations": {"color": "blue"}}},
            {"metadata": {"name": "pod2"}},
            {"metadata": {"name": "pod3", "annotations": {"color": "green"}}},
            {"metadata": {"name": "pod4", "annotations": {"color": "blue"}}},
        ]});
        let t = r#"{.items[?(@.metadata.annotations.color=="blue")].metadata.name}"#;
        assert_eq!(run(t, &data, true).as_deref(), Ok("pod1 pod4"));
        // Fail closed without allow-missing-keys: the missing key is an error.
        assert_eq!(
            run(t, &data, false),
            Err("annotations is not found".to_string())
        );
    }

    #[test]
    fn failures_and_errors() {
        let d = json!({"a": [1, 2, 3], "s": "x"});
        assert_eq!(
            run("{.missing}", &d, false),
            Err("missing is not found".into())
        );
        assert_eq!(run("{.missing}", &d, true).as_deref(), Ok(""));
        assert_eq!(
            run("{end}", &d, false),
            Err("not in range, nothing to end".into())
        );
        assert_eq!(
            run("{.a[5]}", &d, false),
            Err("array index out of bounds: index 5, length 3".into())
        );
        assert_eq!(
            run("{.a[2:1]}", &d, false),
            Err("starting index 2 is greater than ending index 1".into())
        );
        assert_eq!(run("{.a[::0]}", &d, false), Err("step must be > 0".into()));
        assert_eq!(
            run("{.s[0]}", &d, false),
            Err("string is not array or slice".into())
        );
        assert_eq!(
            run("{.a[?(@==1.5)]}", &d, false),
            Err("incompatible types for comparison".into())
        );
        // A malformed template is a parse error, surfaced as-is.
        assert!(run("{.a", &d, false).is_err());
    }

    #[test]
    fn json_output_mode() {
        let d = json!({"items": [{"n": "a<b"}, {"n": "c"}]});
        let mut j = JsonPath::new("t").enable_json_output(true);
        j.parse("{.items[*].n}").unwrap();
        assert_eq!(
            j.execute(&d).unwrap(),
            "[\n    \"a\\u003cb\",\n    \"c\"\n]\n"
        );
    }

    #[test]
    fn go_number_formatting() {
        let d = json!({"a": 100000000.5, "b": 0.00001, "c": 1.5e22, "d": 123456.0});
        check(
            "{.a} {.b} {.c} {.d}",
            &d,
            "1.000000005e+08 1e-05 1.5e+22 123456",
        );
        check(
            "{@}",
            &json!({"x": 1e21, "y": 1e-7}),
            r#"{"x":1e+21,"y":1e-7}"#,
        );
    }
}
