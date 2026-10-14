open! Core
open Webauthn

let%expect_test "W3C vectors: clientDataJSON parses and carries the vector's challenge" =
  List.iter (W3c.all ()) ~f:(fun v ->
    List.iter
      [ "reg", v.registration; "auth", v.authentication ]
      ~f:(fun (which, m) ->
        let c = Client_data.parse (Map.find_exn m "clientDataJSON") |> Or_error.ok_exn in
        printf
          "%-30s %-4s %-15s challenge-ok=%b cross=%b top=%s\n"
          v.name
          which
          c.type_
          (String.equal c.challenge (Map.find_exn m "challenge"))
          c.cross_origin
          (Option.value c.top_origin ~default:"-")));
  [%expect
    {|
    none-es256                     reg  webauthn.create challenge-ok=true cross=false top=-
    none-es256                     auth webauthn.get    challenge-ok=true cross=false top=-
    packed-self-es256              reg  webauthn.create challenge-ok=true cross=false top=-
    packed-self-es256              auth webauthn.get    challenge-ok=true cross=false top=-
    none-es256-crossOrigin         reg  webauthn.create challenge-ok=true cross=true top=-
    none-es256-crossOrigin         auth webauthn.get    challenge-ok=true cross=true top=-
    none-es256-topOrigin           reg  webauthn.create challenge-ok=true cross=true top=https://example.com
    none-es256-topOrigin           auth webauthn.get    challenge-ok=true cross=true top=https://example.com
    none-es256-long-credential-id  reg  webauthn.create challenge-ok=true cross=false top=-
    none-es256-long-credential-id  auth webauthn.get    challenge-ok=true cross=false top=-
    packed-es256                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-es256                   auth webauthn.get    challenge-ok=true cross=false top=-
    packed-es384                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-es384                   auth webauthn.get    challenge-ok=true cross=false top=-
    packed-es512                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-es512                   auth webauthn.get    challenge-ok=true cross=false top=-
    packed-rs256                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-rs256                   auth webauthn.get    challenge-ok=true cross=false top=-
    packed-eddsa                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-eddsa                   auth webauthn.get    challenge-ok=true cross=false top=-
    packed-ed448                   reg  webauthn.create challenge-ok=true cross=false top=-
    packed-ed448                   auth webauthn.get    challenge-ok=true cross=false top=-
    tpm-es256                      reg  webauthn.create challenge-ok=true cross=false top=-
    tpm-es256                      auth webauthn.get    challenge-ok=true cross=false top=-
    android-key-es256              reg  webauthn.create challenge-ok=true cross=false top=-
    android-key-es256              auth webauthn.get    challenge-ok=true cross=false top=-
    apple-es256                    reg  webauthn.create challenge-ok=true cross=false top=-
    apple-es256                    auth webauthn.get    challenge-ok=true cross=false top=-
    fido-u2f-es256                 reg  webauthn.create challenge-ok=true cross=false top=-
    fido-u2f-es256                 auth webauthn.get    challenge-ok=true cross=false top=-
    |}]
;;

let%expect_test "rejections" =
  List.iter
    [ {|not json|}
    ; {|[]|}
    ; {|{"type":"webauthn.get","origin":"https://a"}|}
    ; {|{"type":"webauthn.get","challenge":"+/","origin":"https://a"}|}
    ; {|{"type":1,"challenge":"AA","origin":"https://a"}|}
    ; {|{"type":"webauthn.get","challenge":"AA","origin":"https://a","crossOrigin":"no"}|}
    ; {|{"type":"webauthn.get","challenge":"AA","origin":"https://a","topOrigin":true}|}
    ]
    ~f:(fun s ->
      print_s [%sexp (Result.map (Client_data.parse s) ~f:ignore : unit Or_error.t)]);
  [%expect
    {|
    (Error
     ("clientDataJSON is not JSON"
      ("Yojson__Common.Json_error(\"Line 1, bytes 0-8:\\nInvalid token 'not json'\")")))
    (Error "clientDataJSON is not a JSON object")
    (Error
     ("clientDataJSON: challenge" ("clientDataJSON: missing member" challenge)))
    (Error
     ("clientDataJSON: challenge"
      ("base64url: invalid character" (char +) (position 0))))
    (Error ("clientDataJSON: member is not a string" type))
    (Error "clientDataJSON: crossOrigin is not a boolean")
    (Error "clientDataJSON: topOrigin is not a string")
    |}]
;;

let%test_unit "to_json then parse" =
  let gen =
    let open Quickcheck.Generator.Let_syntax in
    let%map challenge = String.quickcheck_generator
    and origin = String.gen_nonempty' Char.gen_alphanum
    and cross_origin = Bool.quickcheck_generator
    and top_origin = Option.quickcheck_generator (String.gen' Char.gen_print) in
    { Client_data.type_ = "webauthn.create"; challenge; origin; cross_origin; top_origin }
  in
  Quickcheck.test gen ~sexp_of:Client_data.sexp_of_t ~f:(fun c ->
    [%test_result: Client_data.t]
      (Client_data.parse (Client_data.to_json c) |> Or_error.ok_exn)
      ~expect:c)
;;
