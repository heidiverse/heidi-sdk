/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use crate::models::Pointer;
use crate::sdjwt_util;
use crate::{
    claims_pointer::Selector,
    sdjwt_util::{Disclosure, DisclosureTree, SdJwtDecodeError},
};
use heidi_util_rust::value::Value;
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, uniffi::Record, Serialize)]
pub struct SdJwtRust {
    pub claims: Value,
    pub original_jwt: String,
    pub original_sdjwt: String,
    pub keybinding_jwt: Option<String>,
    pub disclosures_map: HashMap<String, Disclosure>,
    pub disclosure_tree: DisclosureTree,
}

impl SdJwtRust {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.claims.clone()).ok()
    }

    pub fn get_as_str(&self, selector: Pointer) -> Option<String> {
        selector
            .select(self.claims.clone())
            .ok()
            .and_then(|a| a.first().cloned())
            .and_then(|a| a.as_str().map(|a| a.to_string()))
    }
}

#[uniffi::export]
pub fn encode_to_json(sdjwt: &SdJwtRust) -> Option<String> {
    let json_val: serde_json::Value = (&sdjwt.claims).into();
    serde_json::to_string(&json_val).ok()
}

#[uniffi::export]
pub fn decode_sdjwt(payload: &str) -> Result<SdJwtRust, SdJwtDecodeError> {
    let decoded = sdjwt_util::decode_sdjwt(payload)?;

    Ok(SdJwtRust {
        claims: decoded.claims.into(),
        original_jwt: decoded.original_jwt,
        original_sdjwt: decoded.original_sdjwt,
        keybinding_jwt: decoded.keybinding_jwt,
        disclosures_map: decoded.disclosure_map,
        disclosure_tree: decoded.disclosure_tree,
    })
}

#[cfg(test)]
mod tests {

    use base64::Engine;
    use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;

    use crate::sdjwt_util::zkp::equality_proof::EqualityProof;

    use super::decode_sdjwt;

    #[test]
    pub fn test_happy_case_disclosures() {
        let jwt_str = "eyJ4NWMiOlsiTUlJQmR6Q0NBUjZnQXdJQkFnSUlVRnhlZWxSbld6WXdDZ1lJS29aSXpqMEVBd0l3THpFTE1Ba0dBMVVFQmhNQ1EwZ3hEekFOQmdOVkJBb01CbFZpYVhGMVpURVBNQTBHQTFVRUF3d0dVbTl2ZEVOQk1CNFhEVEkxTURNd05qQTNNall4T1ZvWERUSTJNRE13TmpBM01qWXhPVm93VlRFUU1BNEdBMVVFQXd3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQ2d3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQnd3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQ0F3SFpDMTBjblZ6ZERFTE1Ba0dBMVVFQmhNQ1EwZ3dXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUzI2WWUzZ2NnTzI5aVlzSExHRmlkT0tPWFl5c29Ddy9MMmZZRmR5UjlhK1R0MFNKUDlpRXhzU2VmMlp2b0c0MkpRanJsT1Rnb0hPckdmYlpkU1M0Sk1NQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQ3IwTmdRbk1GZUFqS1l0cDltODRGNkJwTWRqTTA1ZUlLNGNXUk1mU2FhbEFpQU5VelZpaU5rczVMbzN6ZjFMVmR0ZitFc1RoQW9VaHNmNzAvdVZ1R2w4RUE9PSJdLCJraWQiOiJNRDh3TTZReE1DOHhDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFLREFaVlltbHhkV1V4RHpBTkJnTlZCQU1NQmxKdmIzUkRRUUlJVUZ4ZWVsUm5Xelk9IiwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3N1YW5jZV9kYXRlIjoiMjAyNS0wNC0yMlQxNTo0MDoyMloiLCJ2Y3QiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvY3JlZGVudGlhbHMvcGlkLzEuMCIsImV4cGlyeV9kYXRlIjoiMjAyNS0wNS0wNlQxNTo0MDoyMloiLCJpc3MiOiJodHRwczovL2hlaWRpLWlzc3Vlci13cy1kZXYudWJpcXVlLmNoL2QtdHJ1c3QvYy9FTWt4SXc4TEVDNkR0cVpCT1Z5ZUZ2IiwiX3NkIjpbIi1nTXdCMGJtX01nRUx3TmpGNEc5aFljRzNtQXlaVElpRFlBdnZ5WE1lakEiLCIwLVg5cmNFYV9PandpT3dUM3RCeUZTem00dEFmcWNMdlFyVVN4VklhbEhzIiwiNGgzZlZ6YVJxenF5bjR4bGRWQVpBbEtSd053LWRLSHpmRTQzQWRXZExtbyIsIjVUYTE1MkthVksyTlJmemx6dGtFOTFUNjYxVDlwdGhqNzZkYVpZZkdqLUEiLCI3VHgyZGxvTC1Sc191ZFhDLVg4eWlMS3FJaW5SaW5iSEVNU0Vwb1YxX0RZIiwiQTZDYTFLQUtxZjZ4UFhyTzNrMGhnY0d2blBRMFVlUFlLbW9VQUF6ZnN3WSIsIkVEdl9DY3JrQ0JmcmJDSlVkeU9sdUhXQzJtZTZNbkZFVk5LWUwzbFp4TEEiLCJGalV1UEtoU1BqMUF5Z0dFYVhSQkZGUkREbGw3TXFlTVB2TUxzSzJSNWNnIiwiTVVPRG93YVNZMkNvNlhSZ0VZUDBFbG1mNzJwYUhwLUR4S3JaR29DSGU1VSIsIk8xd2VTWjlxTy0zemFNVjNGcmg4enhNUlJDdDBsZTVXZEVVeDlSYm5Ra2MiLCJVODY0ZlpxR2JQOVNOUEo5UjM1ZUliSDk5R01BWDJod1FLSl9nS2tRcFZ3IiwiWTRVbXpKMHF2NUpaTFJJclpEblFGVkRiRjU5ak5MRmZkV0pSNUVlYm93NCIsIllnOGdrME1POGU2bThzVGtYQldaVlNSTmxranZydWZwUmtZZzBNc0xBZmsiLCJaQUdDOUdKT3RBRkJIeVlmcEpYYThoSHhJRUxTZ1Jwa0FUQTVpRDVKWTdnIiwiX1YzU2syS3k4WTJ2d0lxNFgzOGV3MnRqNUZra0VfOGVQMXp2aGtVT003MCIsIl9yMUtoWU53QjMyekNBRVJaOTJHd18ycTVSMzA1elAzWWVXX3g2bTlBb3ciLCJhR1VoWUljQXd0Z0hpRzhmV0tmSlBNU1A5VVBMM0ROTVNsOG0yN3lrelc4IiwiYVY0ZWktN1hrbEpkeE5yQmJOLTczMWVLTG5SSEtselc0ZVp6VFpOUFhPayIsImRiX3Z0Uk5QQ2ZBdEFYdzlEb3RBWFRKQTh5UWV4WVRqcEhxN0NPSHQwNFEiLCJlUGRLVEgwMkdldEJ4aEEtTFA2MzQ2S1Zjb29nVWRqdDFYb1VkMGJZRlo0Iiwib3VxSGZKVlpZODZheWZ2OFlhZFdwaDJtYmRzNHJxeU9FUFVzaHNWZmRocyJdLCJpc3N1aW5nX2NvdW50cnkiOiJDSCIsImlzc3VpbmdfYXV0aG9yaXR5IjoiQ0giLCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIyN1kzTFpJZ3BRRVgzZUJwMTlCU1hOYUZHc0tld2VIeGxLcHBLclEwelhjIiwieSI6Ikt6c1hDc21LTUMxdFpsN3pxNjB1Z3Z1OTBEU3lIU3Y4ZnlsUkVPejIzdmsifX0sImV4cCI6MTc0NjU0NjAyMiwic2NoZW1hX2lkZW50aWZpZXIiOnsiY3JlZGVudGlhbElkZW50aWZpZXIiOiJlYy1waWQtdHZreWkiLCJ2ZXJzaW9uIjoiMy4wLjAifSwiaWF0IjoxNzQ1MzM2NDIyLCJyZW5kZXIiOnsidHlwZSI6Ik92ZXJsYXlzQ2FwdHVyZUJ1bmRsZVYxIiwib2NhIjoiaHR0cHM6Ly9oZWlkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9vY2EvSUEwLWwxWEUteUVrcHNfcEJxbUtaNFNNWDlOWV95R1ZrSDJVaVR6b3cxNmkuanNvbiJ9fQ.Z_pFo29d9NyG6SudyvV0MKCHhpm9tXspWQpKnerHSsP-_dNoV8tQZSz3fKj0osg3uFTjsI67JxUBkxPQIlJoHA~WyItUW0xQ3hEOEc1ZG01UlN0MmNtaFVRIiwiYWdlX2VxdWFsX29yX292ZXIiLHsiX3NkIjpbIkY3QnZ1QmpLYk82VWNYZm5RMzhoZnphY3lHX2RITzVMRUFCeUhCakVsQ2siLCJMVXpuN1R1cGlMNU9PRzRpTVB5RzZ4bnp1MVJzLU5sYUF6RFc2Z2hvMEFvIiwidW5BMHBta2NFM3RUWTdHMlltZFZjck42bFFRbWVoc3liUUdNckF5WWR6QSIsInlEMXhmSDhINUR6eUdxVy02YXRQYTEyYmlHSEstRkdyUU1LdzFRNDNsN2MiXX1d~WyJ0MGZlWF94aVNZZVZEYmxXdlJSN01nIiwiMTYiLHRydWVd~WyJvUlJzSjVxRXhWMUozdG5jd3pjdkNRIiwiZmFtaWx5X25hbWUiLCJGYW1pbGl5IE5hbWUiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJYNTA5X3Nhbl9kbnM6aGVpZGktdmVyaWZpZXItd3MtZGV2LnViaXF1ZS5jaCIsImlhdCI6MTc0NTQxNTM3Mywibm9uY2UiOiJtT2VsZkZvd3d0a3NKdU9SU1M3TDdnIiwic2RfaGFzaCI6InBkbmt2WFN3U29DMWtoY2FwaTNWVkdaZG5jeVA5M2dCRWpPWkFobU5VRmcifQ.909R8ATX5RAz22boGlT3qb5dt62TRhKDlzASrqrb7BB0X_Xg_0x0lK4Xrs3-1PUALC6Rpyc7Wnnem6YIz8D1Ww";
        let parsed_jwt = decode_sdjwt(jwt_str).unwrap();
        assert_eq!(parsed_jwt.disclosures_map.len(), 3);
    }

    #[test]
    pub fn test_empty_disclosures() {
        let jwt_str = "eyJ4NWMiOlsiTUlJQmFEQ0NBUTZnQXdJQkFnSUlTbTVwN3lhaDdoTXdDZ1lJS29aSXpqMEVBd0l3THpFTE1Ba0dBMVVFQmhNQ1EwZ3hEekFOQmdOVkJBb01CbFZpYVhGMVpURVBNQTBHQTFVRUF3d0dVbTl2ZEVOQk1CNFhEVEkxTURRd01UQTVOVGd3TkZvWERUSTJNRFF3TVRBNU5UZ3dORm93UlRFTU1Bb0dBMVVFQXd3RGVuWjJNUXd3Q2dZRFZRUUtEQU42ZG5ZeEREQUtCZ05WQkFjTUEzcDJkakVNTUFvR0ExVUVDQXdEZW5aMk1Rc3dDUVlEVlFRR0V3SkRTREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRzNENjhhNzVPelU4OU1Uc1hlelpkWEZkbTBlY1FUek1pd2gyMFdKR2ZpbGpXMks3Zmt5Rmdzb0E2TTBOMkdscEFCU0d5eVBsOG04bnA0THlNRnpocWd3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnZkFUdWh3NjlUYW1mWWJoR2hwQ0FSdGV2Z1lrV3hmNTRiSXRQUEVmemdFc0NJUUNjTVhyQm9KYUdwRkdMZFcwRFJmb1NZOUFkbHovNVJCRlBDeUVtOHBsUWx3PT0iXSwia2lkIjoiTUQ4d002UXhNQzh4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRS0RBWlZZbWx4ZFdVeER6QU5CZ05WQkFNTUJsSnZiM1JEUVFJSVNtNXA3eWFoN2hNPSIsInR5cCI6ImRjK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJpc3N1YW5jZV9kYXRlIjoiMjAyNS0wNC0yNVQwOToyMDoyN1oiLCJ2Y3QiOiJ0ZXN0LWp3dCIsImV4cGlyeV9kYXRlIjoiMjAyNS0wNS0wOVQwOToyMDoyN1oiLCJpc3MiOiJodHRwczovL2hlaWRpLWlzc3Vlci13cy1kZXYudWJpcXVlLmNoL3p2di9jL3gyRWg0NEcwZ3U5VEVXWGZnYWpUMlUiLCJfc2QiOlsiNGdpZG9IY2NpUllmZFRTSDFYd2c5ZzVIbGZneTdVenFOUC1sV0ZPNm12dyIsIjZQX0hPTnl4SEM3Z2NUMVF1UmF4dzVLbHFRSmh4cFJJQlhscXhjYndFYTgiXSwiaXNzdWluZ19jb3VudHJ5IjoiQ0giLCJpc3N1aW5nX2F1dGhvcml0eSI6IkNIIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoic25UU1doenFHZEJrYlZaUjROckt5ZXVkcEtQeUIxSWptR3VMeURNSkVWUSIsInkiOiJhUEFmcm8xNFRRRGc1QzVJQmJFSFNUaGJ5LTl3LXpvWjlNMTNUMmhOcHc0In19LCJleHAiOjE3NDY3ODI0MjcsInNjaGVtYV9pZGVudGlmaWVyIjp7ImNyZWRlbnRpYWxJZGVudGlmaWVyIjoiYXNkYXNkLXJvbTBvIiwidmVyc2lvbiI6IjIuMS4wIn0sImlhdCI6MTc0NTU3MjgyNywicmVuZGVyIjp7InR5cGUiOiJPdmVybGF5c0NhcHR1cmVCdW5kbGVWMSIsIm9jYSI6Imh0dHBzOi8vaGVpZGktaXNzdWVyLXdzLWRldi51YmlxdWUuY2gvb2NhL0lBcEc2TEJHelZQVVhSMUFINEdqd0xOMENTR2s2THRob21iUHlfc29EaG9sLmpzb24ifSwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7InVyaSI6Imh0dHBzOi8vaGVpZGktaXNzdWVyLXdzLWRldi51YmlxdWUuY2gvdjEvc3RhdHVzbGlzdC90b2tlbiIsImlkeCI6NTYwODUxMH19fQ.Xp8kghKINyX9RXKSVY5qdato4lDFbj6HLQytI9mXQOy6CxGNc0aKHhuq9D05_PqHmt0cFoND2i4Lv48Msjhupw~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJYNTA5X3Nhbl9kbnM6aGVpZGktdmVyaWZpZXItd3MtZGV2LnViaXF1ZS5jaCIsImlhdCI6MTc0NTU3NTY3Mywibm9uY2UiOiJRLVNLd0FQVUUtWl84WUZRY2dlN0N3Iiwic2RfaGFzaCI6Imc4WmI3VWxIRXNZQVg1QUw3U19aMkI4X1dCUnFpajFEUFFOcW1JdWl5RlUifQ.vqSMwsrj0lkzHc0Iphe78dvei_CvAbmAsnZndM8uSmpnl3geBz_z4Rigblop-zkpDb0M3MApMFt4LoucpBbBUQ";
        let parsed_jwt = decode_sdjwt(jwt_str).unwrap();
        assert_eq!(parsed_jwt.disclosures_map.len(), 0);
    }
    #[test]
    pub fn test_pedersen_disclosures() {
        let jwt_str = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiZUdDS25YRkNBakRER0t2M2xmU2RfQmZPZXZ2TVVjODBlT3ljazRXTV9EayIsIml0LU9vV1NxcHFVcVA3eFByc3RqUlZ1c21TYWlvbllaV2lDRHl3V2RJV0EiXSwiX3NkX2FsZyI6ImVjX3BlZGVyc2VuIiwiX3NkX2FsZ19wYXJhbSI6eyJjb21taXRtZW50X3NjaGVtZSI6eyJwdWJsaWNfcGFyYW1zIjp7ImciOiJOcGlJMGdQa0JVbVhaS0liT2NMN0hSZmE4Q28yYjVpcVNVWkpXTGo2a25nIiwiaCI6IktFaXdHUHFDc3BENFcyNnRCQ3V0RFQ3M2tROWZ2N0kwcEJVcERPbHg0bDAifSwiY3J2IjoiZWQyNTUxOSJ9fSwiY29tX2xpbmsiOnsidGVzdCI6MCwiZG9iIjoxfSwiaXNzIjoic2FtcGxlX2lzc3VlciIsImlhdCI6MTc2ODM4Mjg0NSwibmJmIjoxNzY4MzgyNTQ1LCJleHAiOjE3NjgzODMyMDV9.hct1RNSY3wSpNMMal2Tb-fJONQ8fJIEkWUopvmwCAcSJNJHvgt369OUT4faepORcD0-4dFXEJHV89jq_L6e_uw~WyJzeV85SWZDeW5BdnRhUUo2VDl2bU9NWVM1X0R6Z1BkRUFkUDc1MmRRTlFZIiwidGVzdCIsImFiYyJd~WyJKYlRJYW9qZWt0TmdkdlBpXzhfZkZhLU5LYndMVkwtZWFsYVk3MXRNZVFvIiwiZG9iIiwxOTU4XQ~";
        let parsed_jwt = decode_sdjwt(jwt_str).unwrap();
        println!("{:#?}", parsed_jwt.claims);
        println!("{:#?}", parsed_jwt.disclosures_map);
        assert_eq!(parsed_jwt.disclosures_map.len(), 2);
    }
    #[test]
    pub fn test_kmp_issued_sdjwt() {
        let jwt_str = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMCwibmF0aW9uYWxpdGllcyI6W3siLi4uIjoiNmpYS0JocGcxOWVTdHBLWmVPOWRzcExlWTQ0SjVBX0dMRzNBWDROVnMyayJ9LHsiLi4uIjoiSEREWWVfdnVWUXVsWEJLSjJ2YWtKY3dIUXBTZFNPRVdOZkVpMlFveFkwbyJ9XSwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkhaVEo0dkpkMkI0a1QyQXd1cngya0xUT2I4b0I5RzliYXR3TkJrcHQtV3ciLCJ5IjoiX3VobTBvakVRZnN4ZkszNmpobm9LdVY4U1VRQTBSaldDOWhQZVR0Z1djWSJ9fSwiX3NkIjpbInlDTTBFTHlNRnJQWE5SMHJGcVZ2eGFMYlM2SEdMWnRTYWlLQnEyWVBEQU0iLCJySXotR0NMYkhkbjBsT3h0NUFocXlRRnpuS2g2dzBGZ2xNZlp2OWEzdm53IiwiWnRNT3RmM21zYjdoUk9NVnRGTWFHV0xYT1E1bDFrSng4bVg1YmZwaFhTOCIsIlZrTE5mT0NlOFRGN0xWUGNaX25RcEV1ajNpSVRCemVWMkk1eWN3MTROWG8iLCI4bFMyMGJabFFrVVQ5WEFXVERMRGViT0w3Rl9NQjZhSkUzQzlneUhzSFhZIiwick9wem44RHMzWk9kY09RVmN5M3o3Zzl3UENIMkltVTdQbW5xZjJud09WVSIsIk5PMkFUbmpoWnVTTVZjak5vaHMwTVJ2b21WRlJGdEpXQXVmUGdwVS1SU2ciLCJlcXpaWnhRTFVzay1PbE9vZHZONlVSS1hYZ2tlTmd2UldwckVHOVhCVFRFIl0sIl9zZF9hbGdfcGFyYW0iOnsiY29tbWl0bWVudF9zY2hlbWUiOnsicHVibGljX3BhcmFtcyI6eyJoIjoicUJXVHp3NTJDbGl5WWR6NHc5U1gwcmxMb1loVndnazZMMWx2VWlfejFVOCIsImciOiJuR3hsUEFKV2k3TGFLbDk1bnpwSGNxUFF1ZW5ac2p3aUExWDNXalFUbGxvIn0sImNydiI6ImVkMjU1MTkifX0sIl9zZF9hbGciOiJlY19wZWRlcnNlbiJ9.c0pi8wDKtI5r6qoFnBMixrkygklboXhZUhU7OgRFpq4U6V9qQcQKiKyEkayqZNV9CXEEz8mXfEQpXQ-QF1IUVA~WyJ3X2R4MkpVSzF2cWlCeWF3elA1SFhKTS14VmxuWkZnV2ZXRDRCRmc3ZUF3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJVRlJUdTRPdzFtb0IxSHZQaDVZcTFDdEh2dk04dHJqX3NfRlZDUmV6aUFRIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI0NHhjaVhlWi1mdEllcnlnazFpdE1qMEl0RTJTbFZvWURiV0wzc2xaTWcwIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJkR1VhbUVhaEw0YnpRV2F2aDIxbkJRZ055QV96YlFGMmlBU2MyREJoVHdnIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyJNTTJBbVVldWNHNXlEZTRtQkZYRzFxMWx4VHJPR1laQWprWktvMXhocWd3IiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIix0cnVlXQ~WyIzbkc2U2F1MTMtcEd4eWlJeVVVTExhVTlWUlB5UFNwdWFlSnBpRWliMVFRIiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~WyJMQ1Rxa0pXYXVHMFF0ZVBkbGxQZkZ4RXMwUGZPWFZaM0J1NmdBTjlsRkFZIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJueHBLMVVOeE8xVlAzODhPZVU2dWZmYVdETjJXYjlTY2x4U3VITHhKRGdJIiwiVVMiXQ~WyJGenowNXE5RGV6RzBvS0xBNURmX24tNkVDLWxwejAxYnoyN0ttMVZOOVE0IiwiREUiXQ~WyJLcWZYXzNWWVBzS3hxUHRfOGhxQTFKQjJLUnlMei1rVTlwY18xbFBaQkFJIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiNmpYS0JocGcxOWVTdHBLWmVPOWRzcExlWTQ0SjVBX0dMRzNBWDROVnMyayJ9LHsiLi4uIjoiSEREWWVfdnVWUXVsWEJLSjJ2YWtKY3dIUXBTZFNPRVdOZkVpMlFveFkwbyJ9XV0~";
        let parsed_jwt = decode_sdjwt(&jwt_str).unwrap();
        println!("{:#?}", parsed_jwt.claims);
        println!("{:#?}", parsed_jwt.disclosures_map);
    }
    #[test]
    pub fn test_equality_proof() {
        let jwt_str1 = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiX0tkcnVIUkZlTlVIZTNnajJNUXZ1WTdhV08wQ3pDUENVaUJoTG15M3B6cyIsIi11Um9TNzNER3AzRjB0RFVBNFNsNkp4azhnNXBCRXpxWDJqci02MWVzbDAiXSwiX3NkX2FsZyI6ImVjX3BlZGVyc2VuIiwiX3NkX2FsZ19wYXJhbSI6eyJjb21taXRtZW50X3NjaGVtZSI6eyJwdWJsaWNfcGFyYW1zIjp7ImciOiJBaTJpcWlFX3paMVRHYWVfRzBDOUhKZTE0aThoTWx3M3hwcFVuZjhPcUI0IiwiaCI6Im5PblFYeEZQV0UyX3k0NnJoVm81UTUtNXNGYWJFNEgtc21oLTBQeTBqVVkifSwiY3J2IjoiZWQyNTUxOSJ9fSwiY29tX2xpbmsiOnsidGVzdCI6MCwiZG9iIjoxfSwiaXNzIjoic2FtcGxlX2lzc3VlciIsImlhdCI6MTc2ODM4NTA4NiwibmJmIjoxNzY4Mzg0Nzg2LCJleHAiOjE3NjgzODU0NDZ9.6E4YLwsTJrSuZ3MM9VKjuwHPGhzSMd9cVFHDoHQKrysbuEL01VNRUXpiRYzV7STwbkFTVtt7WsR6sTE81BBqOw~WyItNllMWjhoeUtCbU91VkxmT0NsdnhKM2w0bUNNNVJhUjdTRmVMenpLUVFNIiwidGVzdCIsImFiYyJd~WyJmeF9wSkdtSHlHS0dWVS1SdmFyX19JT1FadF9LejRycm11ejhCenZWYkE0IiwiZG9iIiwxOTU4XQ~";
        let jwt_str2 = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiTXUwajFIamJ2UnpTWEFLUWxlQ3I4NVkxOTZqdTEwTUNaSzdCRHgyRHZVNCIsImtQN21OZTBLRnJlc25KMjYxaDIxM1lvZ1NqX196dHVQZDQ3c3ByU2V4V1UiXSwiX3NkX2FsZyI6ImVjX3BlZGVyc2VuIiwiX3NkX2FsZ19wYXJhbSI6eyJjb21taXRtZW50X3NjaGVtZSI6eyJwdWJsaWNfcGFyYW1zIjp7ImciOiJxa2IxX1daRnNLVFY4QW1RRkVaRDNvOUl1UnJ2NkNoMTZucFgxb1pDTDBBIiwiaCI6IjlQVGQ3dFdVR3JROElMUkhKY0NKUDVPMjBjUkpXOXpmaG00VmZHV2hzSEkifSwiY3J2IjoiZWQyNTUxOSJ9fSwiY29tX2xpbmsiOnsidGVzdCI6MCwiZG9iIjoxfSwiaXNzIjoic2FtcGxlX2lzc3VlciIsImlhdCI6MTc2ODM4NjgwMSwibmJmIjoxNzY4Mzg2NTAxLCJleHAiOjE3NjgzODcxNjF9.tp2wQQYsoRxK5lVtvtTQ6tvC9GAjcazQgbARA16CdP00EYXGdYRsnPShbBbB_1UYLJmvT_513nV46ZLewAvxvQ~WyJpRlFUak83RlVwYWNBeHVkWTFaaDNuUlNIVlBQNGRISTY5bk4zc2UzOEEwIiwidGVzdCIsImFiY2UiXQ~WyJ5MEctTnFNU3c1RDY5VUIzSmxCU0llcGhnU0EwOHdjN2hqckszOGpuYndRIiwiZG9iIiwxOTU4XQ~";
        let sdjwt1 = decode_sdjwt(jwt_str1).unwrap();
        println!("{:?}", sdjwt1.disclosures_map);
        let sdjwt2 = decode_sdjwt(jwt_str2).unwrap();
        let equality_proof =
            EqualityProof::from_sdjwts("dob", &sdjwt1, &sdjwt2, vec![0xde, 0xad]).unwrap();
        let serialized = equality_proof.as_bytes();
        let deserialized_proof = EqualityProof::from_bytes(&serialized);

        let g1 = sdjwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h1 = sdjwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let g2 = sdjwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h2 = sdjwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let g1 = BASE64_URL_SAFE_NO_PAD.decode(g1).unwrap();
        let h1 = BASE64_URL_SAFE_NO_PAD.decode(h1).unwrap();
        let g2 = BASE64_URL_SAFE_NO_PAD.decode(g2).unwrap();
        let h2 = BASE64_URL_SAFE_NO_PAD.decode(h2).unwrap();
        let mut challenge_bytes = vec![];
        challenge_bytes.extend_from_slice("dob".as_bytes());
        challenge_bytes.extend_from_slice(&g1);
        challenge_bytes.extend_from_slice(&h1);
        challenge_bytes.extend_from_slice(&g2);
        challenge_bytes.extend_from_slice(&h2);
        challenge_bytes.extend_from_slice(&vec![0xde, 0xad]);
        assert!(deserialized_proof.verify(challenge_bytes, "dob", &sdjwt1, &sdjwt2));
    }
}
