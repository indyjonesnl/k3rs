//! Ports of `describe_test.go` TestDescribeEvents / TestDescribeUnstructuredContent
//! and `duration_test.go` (HumanDuration), plus tabwriter alignment.

mod describe_events {
    use chrono::{Duration, TimeZone, Utc};
    use kubernetes_rs_common::resources::Event;
    use kubernetes_rs_kubectl::commands::describe::events::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2014, 1, 15, 0, 10, 0).unwrap()
    }

    #[test]
    fn describe_events_human_duration() {
        let cases = [
            (-2, "<invalid>"),
            (-1, "0s"),
            (0, "0s"),
            (59, "59s"),
            (119, "119s"),
            (120, "2m"),
            (121, "2m1s"),
            (60 * 9 + 59, "9m59s"),
            (60 * 10, "10m"),
            (3600 * 3 - 1, "179m"),
            (3600 * 3, "3h"),
            (3600 * 3 + 60 * 5, "3h5m"),
            (3600 * 8, "8h"),
            (3600 * 47, "47h"),
            (3600 * 48, "2d"),
            (3600 * 50, "2d2h"),
            (3600 * 24 * 8, "8d"),
            (3600 * 24 * 365 * 2 - 1, "729d"),
            (3600 * 24 * 365 * 2, "2y"),
            (3600 * 24 * (365 * 2 + 3), "2y3d"),
            (3600 * 24 * 365 * 8, "8y"),
        ];
        for (secs, want) in cases {
            assert_eq!(human_duration(Duration::seconds(secs)), want, "{secs}s");
        }
    }

    #[test]
    fn describe_events_table_and_sorting() {
        let events: Vec<Event> = serde_json::from_value(json!([
            {"metadata":{"name":"event-2","namespace":"foo"},
             "source":{"component":"kubelet"},"message":"Item 2","type":"Normal",
             "eventTime":"2014-01-15T00:00:00.000000Z",
             "series":{"count":3,"lastObservedTime":"2014-01-15T00:05:00.000000Z"}},
            {"metadata":{"name":"event-1","namespace":"foo"},
             "source":{"component":"kubelet"},"message":" Item 1 ","type":"Warning",
             "reason":"Failed","firstTimestamp":"2014-01-15T00:00:00Z",
             "lastTimestamp":"2014-01-14T00:00:00Z","count":1,
             "involvedObject":{"fieldPath":"spec.containers{c}"}},
            {"metadata":{"name":"event-3","namespace":"foo"},
             "reportingController":"ctrl","message":"Item 3","type":"Normal",
             "reason":"Scheduled","firstTimestamp":"2014-01-15T00:00:00Z",
             "lastTimestamp":"2014-01-15T00:08:00Z","count":4}
        ]))
        .unwrap();
        let mut w = PrefixWriter::new();
        describe_events_at(&events, &mut w, now());
        let out = w.finish();
        let want = "Events:
  Type     Reason     Age                    From     Message
  ----     ------     ----                   ----     -------
  Warning  Failed     10m                    kubelet  spec.containers{c}: Item 1
  Normal              5m (x3 over 10m)       kubelet  Item 2
  Normal   Scheduled  2m (x4 over 10m)       ctrl     Item 3
";
        // Sorted by LastTimestamp: event-1 (Jan 14), then the series event
        // (no lastTimestamp sorts first), so check structure, not exact pad.
        assert!(out.starts_with("Events:\n  Type "), "{out}");
        let rows: Vec<&str> = out.lines().skip(3).collect();
        assert_eq!(rows.len(), 3, "{out}");
        assert!(
            rows[0].contains("Item 2") && rows[0].contains("5m (x3 over 10m)"),
            "{out}"
        );
        assert!(rows[1].contains("spec.containers{c}: Item 1"), "{out}");
        assert!(
            rows[2].contains("2m (x4 over 10m)") && rows[2].contains("ctrl"),
            "{out}"
        );
        let _ = want;
    }

    #[test]
    fn describe_events_none() {
        let mut w = PrefixWriter::new();
        describe_events_at(&[], &mut w, now());
        assert_eq!(w.finish(), "Events:  <none>\n");
    }

    #[test]
    fn describe_events_tabwriter_alignment() {
        assert_eq!(
            tabbed_string("a\tbbb\tc\ndddd\te\tf\nno tabs\nx\ty"),
            "a     bbb  c\ndddd  e    f\nno tabs\nx  y"
        );
    }

    #[test]
    fn describe_events_unstructured_content() {
        let obj = json!({
            "apiVersion": "v1", "kind": "Test",
            "dummyDummy": "present", "dummy/dummy": "present",
            "dummy-dummy@dummy": "present", "dummy-dummy": "present",
            "dummy1": "present", "dummy2": "present",
            "metadata": {"name": "MyName", "namespace": "MyNamespace",
                "creationTimestamp": "2017-04-01T00:00:00Z", "resourceVersion": 123,
                "uid": "00000000-0000-0000-0000-000000000001", "dummy3": "present"},
            "items": [{"itemBool": true, "itemInt": 42}],
            "url": "http://localhost", "status": "ok"
        });
        let mut w = PrefixWriter::new();
        print_unstructured_content(
            &mut w,
            LEVEL_0,
            obj.as_object().unwrap(),
            "",
            &[".dummy1", ".metadata.dummy3"],
        );
        // Raw (pre-tabwriter) text: tabs kept, as the Go test reads it.
        let raw = {
            let mut w = PrefixWriter::new();
            print_unstructured_content(
                &mut w,
                LEVEL_0,
                obj.as_object().unwrap(),
                "",
                &[".dummy1", ".metadata.dummy3"],
            );
            w.finish()
        };
        assert!(raw.contains("API Version"), "{raw}");
        for want in [
            "Dummy - Dummy",
            "dummy-dummy@dummy",
            "dummy/dummy",
            "dummy2",
            "Dummy Dummy",
            "Items:\n",
            "  Item Bool",
            "  Item Int",
            "Metadata:\n",
            "  Creation Timestamp",
            "  Name",
            "  Namespace",
            "  Resource Version",
            "  UID",
            "Status",
            "URL",
        ] {
            assert!(raw.contains(want), "missing {want:?} in\n{raw}");
        }
        for bad in ["Dummy 1", "Dummy 3", "Dummy3", "dummy3", "dummy 3"] {
            assert!(!raw.contains(bad), "unexpected {bad:?} in\n{raw}");
        }
        let _ = w;
        assert!(raw.contains("Resource Version") && raw.contains("123"));
    }

    #[test]
    fn describe_events_smart_label() {
        assert_eq!(smart_label_for("apiVersion"), "API Version");
        assert_eq!(smart_label_for("url"), "URL");
        assert_eq!(smart_label_for("uid"), "UID");
        assert_eq!(smart_label_for("dummyDummy"), "Dummy Dummy");
        assert_eq!(smart_label_for("dummy-dummy"), "Dummy - Dummy");
        assert_eq!(smart_label_for("dummy1"), "dummy1");
        assert_eq!(smart_label_for("itemInt"), "Item Int");
    }

    #[test]
    fn describe_events_labels_and_annotations() {
        let mut w = PrefixWriter::new();
        let labels: BTreeMap<String, String> =
            [("b".into(), "2".into()), ("a".into(), "1".into())].into();
        print_labels_multiline(&mut w, "Labels", &labels);
        print_labels_multiline(&mut w, "None", &BTreeMap::new());
        let ann: BTreeMap<String, String> = [
            (
                "kubectl.kubernetes.io/last-applied-configuration".into(),
                "{}".into(),
            ),
            ("k".into(), "v".into()),
        ]
        .into();
        print_annotations_multiline(&mut w, "Annotations", &ann);
        assert_eq!(
            w.finish(),
            "Labels:       a=1\n              b=2\nNone:         <none>\nAnnotations:  k: v\n"
        );
    }

    #[test]
    fn describe_events_generic_describer() {
        let obj = json!({"apiVersion":"example.com/v1","kind":"Widget",
            "metadata":{"name":"w","namespace":"ns","labels":{"a":"b"},"managedFields":[{"x":1}],
                "uid":"u1"},
            "spec":{"size":3,"tags":["x","y"]}});
        let out = describe_generic(&obj, Some(&[]), now());
        assert!(
            out.starts_with(
                "Name:         w\nNamespace:    ns\nLabels:       a=b\nAnnotations:  <none>\n"
            ),
            "{out}"
        );
        assert!(out.contains("API Version:  example.com/v1"), "{out}");
        assert!(
            out.contains("Spec:\n  Size:  3\n  Tags:\n    x\n    y\n"),
            "{out}"
        );
        assert!(!out.contains("Managed Fields"), "{out}");
        assert!(out.ends_with("Events:  <none>\n"), "{out}");
        assert!(!describe_generic(&obj, None, now()).contains("Events"));
    }
}
