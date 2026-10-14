open! Core

type t =
  | Malformed of string
  | Wrong_ceremony of
      { expected : string
      ; got : string
      }
  | Challenge_mismatch
  | Challenge_expired
  | Origin_not_allowed of string
  | Cross_origin_not_allowed
  | Top_origin_not_allowed of string
  | Rp_id_mismatch
  | User_not_present
  | User_not_verified
  | Invalid_backup_flags
  | Backup_eligibility_changed
  | Missing_credential_data
  | Credential_id_mismatch
  | Unsupported_algorithm of int
  | Algorithm_not_allowed of int
  | Unsupported_attestation of string
  | Invalid_attestation of string
  | Credential_not_allowed
  | User_handle_mismatch
  | Missing_user_handle
  | Bad_signature
  | Sign_count_regressed of
      { stored : int
      ; received : int
      }
[@@deriving sexp, compare, equal]

let code = function
  | Malformed _ -> "malformed"
  | Wrong_ceremony _ -> "wrong_ceremony"
  | Challenge_mismatch -> "challenge_mismatch"
  | Challenge_expired -> "challenge_expired"
  | Origin_not_allowed _ -> "origin_not_allowed"
  | Cross_origin_not_allowed -> "cross_origin_not_allowed"
  | Top_origin_not_allowed _ -> "top_origin_not_allowed"
  | Rp_id_mismatch -> "rp_id_mismatch"
  | User_not_present -> "user_not_present"
  | User_not_verified -> "user_not_verified"
  | Invalid_backup_flags -> "invalid_backup_flags"
  | Backup_eligibility_changed -> "backup_eligibility_changed"
  | Missing_credential_data -> "missing_credential_data"
  | Credential_id_mismatch -> "credential_id_mismatch"
  | Unsupported_algorithm _ -> "unsupported_algorithm"
  | Algorithm_not_allowed _ -> "algorithm_not_allowed"
  | Unsupported_attestation _ -> "unsupported_attestation"
  | Invalid_attestation _ -> "invalid_attestation"
  | Credential_not_allowed -> "credential_not_allowed"
  | User_handle_mismatch -> "user_handle_mismatch"
  | Missing_user_handle -> "missing_user_handle"
  | Bad_signature -> "bad_signature"
  | Sign_count_regressed _ -> "sign_count_regressed"
;;

let all_codes =
  List.map
    ~f:code
    [ Malformed ""
    ; Wrong_ceremony { expected = ""; got = "" }
    ; Challenge_mismatch
    ; Challenge_expired
    ; Origin_not_allowed ""
    ; Cross_origin_not_allowed
    ; Top_origin_not_allowed ""
    ; Rp_id_mismatch
    ; User_not_present
    ; User_not_verified
    ; Invalid_backup_flags
    ; Backup_eligibility_changed
    ; Missing_credential_data
    ; Credential_id_mismatch
    ; Unsupported_algorithm 0
    ; Algorithm_not_allowed 0
    ; Unsupported_attestation ""
    ; Invalid_attestation ""
    ; Credential_not_allowed
    ; User_handle_mismatch
    ; Missing_user_handle
    ; Bad_signature
    ; Sign_count_regressed { stored = 0; received = 0 }
    ]
;;

let to_error t =
  Error.create_s [%message "WebAuthn verification failed" ~code:(code t) (t : t)]
;;
