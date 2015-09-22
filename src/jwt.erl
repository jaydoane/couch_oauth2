-module(jwt).

-compile([export_all]).

-include_lib("jose/include/jose.hrl").

decode_jwt_test() ->
    %% from MobileFirst TAI/imf-oauth-common/src/test/java/com/worklight/oauth/token/TokenDecoderTest.java
    AccessToken = <<"eyJhbGciOiJSUzI1NiIsImpwayI6eyJhbGciOiJSU0EiLCJleHAiOiJBUUFCIiwibW9kIjoiQUpxZGpMVW1iQmRZaGQ1Rk42akFuYmFPU0JuZGN2ZWh3amY2UzhNWWxCaVlwRUVyTXhDZ1ZxNERGeFZ6eldTZmFWM0d1emJYTzM4YjRKUUl1dlhrOE91SXNLLW01cDdFcjV4dVZGeFNkakNNR1Q5TGxMLU9UVXZISUdmWUdCNk1BeGtHWG96QTZHMmUtcktsdmdGelRZX29CczBYVF9DdWlqTE1hUlV6MWVER3pxR0VBb05WSXVBb3p6SGJLVmxMbG5ydUpySjAwdGtpeFZVRUdyVUo0Q0tkN2JlUHZXclBPT1hBck5MR0twN08yakxvbjN1VDI0clExVTVwT2ZwdGVwLXR1UWI5enhETlpya3lEMHFsMWxuOW5zcS1NWmt5Z2xoZVEwRm9EUWZ6TG1pNlhJclVfbzktd2VmcWI1c1RJTDVHcklSZHVTQ1AzMXlhbC1jeXRUVSJ9fQ.eyJleHAiOjE0NTk1NTY5MjcsImltZi5zY29wZSI6eyJ3bF9kaXJlY3RVcGRhdGVSZWFsbSI6eyJleHAiOjE0NTk1NTY5MjcsIm1hbmRhdG9yeSI6dHJ1ZX0sIlN1YnNjcmliZVNlcnZsZXQiOnsiZXhwIjoxNDU5NTU2OTI3LCJtYW5kYXRvcnkiOnRydWV9LCJ3bF9hdXRoZW50aWNpdHlSZWFsbSI6eyJleHAiOjE0NTk1NTY5MjcsIm1hbmRhdG9yeSI6dHJ1ZX0sIndsX3JlbW90ZURpc2FibGVSZWFsbSI6eyJleHAiOjE0NTk1NTY5MjcsIm1hbmRhdG9yeSI6dHJ1ZX0sIlNhbXBsZUFwcFJlYWxtIjp7ImV4cCI6MTQ1OTU1NjkyNywibWFuZGF0b3J5Ijp0cnVlfSwid2xfYW50aVhTUkZSZWFsbSI6eyJleHAiOjE0NTk1NTY5MjcsIm1hbmRhdG9yeSI6dHJ1ZX0sIndsX2RldmljZUF1dG9Qcm92aXNpb25pbmdSZWFsbSI6eyJleHAiOjE0NTk1NTY5MjcsIm1hbmRhdG9yeSI6dHJ1ZX0sIndsX2RldmljZU5vUHJvdmlzaW9uaW5nUmVhbG0iOnsiZXhwIjoxNDU5NTU2OTI3LCJtYW5kYXRvcnkiOnRydWV9LCJ3bF9hbm9ueW1vdXNVc2VyUmVhbG0iOnsiZXhwIjoxNDU5NTU2OTI3LCJtYW5kYXRvcnkiOnRydWV9fSwiaXNzIjoiaHR0cDpcL1wvOS4xMTEuMjcuMTYyOjEwMDgwXC93b3JrbGlnaHRcL2F1dGhvcml6YXRpb25cL3YxXC90ZXN0dG9rZW4iLCJwcm4iOiJ0ZXN0Q2xpZW50NDAxNTUwMzE1In0.A43MIeTh7V7YUHdsyFrcXumJ1DgiFoLBDHyAaHNmJjE0PlvE1sA0UDxXorXVmEKOMzNvi99rfcC9aLobYHkcC_Vdwp5FfwI8va5g58JDrA8Bcl4J9L65xVyOyUWt5eh2bRgkOPwN13qGSmR_xsKVYe1eq7cpFHpftjhePBh8MNuFKUful-FrJFmK5Dq9ffq4IfiIJVI3RnVcjxWNIdklBCQQGsb8Hw60gadriYGeRSG0uBVBNVPfFM3l9At9hdxkeoKyA8rOBadzC0rR5T7LntM9fBUq15nmU0xA66sFJ88Zp1uXo1NWcG3X9M73BS-WIG1dOf7i2WpZ80p8i56Hxg">>,
    %% from MobileFirst TAI/imf-oauth-common/src/test/java/com/worklight/oauth/token/MockTAIUtil.java
    Key = <<"{\"e\":\"AQAB\",\"n\":\"AJqdjLUmbBdYhd5FN6jAnbaOSBndcvehwjf6S8MYlBiYpEErMxCgVq4DFxVzzWSfaV3GuzbXO38b4JQIuvXk8OuIsK-m5p7Er5xuVFxSdjCMGT9LlL-OTUvHIGfYGB6MAxkGXozA6G2e-rKlvgFzTY_oBs0XT_CuijLMaRUz1eDGzqGEAoNVIuAozzHbKVlLlnruJrJ00tkixVUEGrUJ4CKd7bePvWrPOOXArNLGKp7O2jLon3uT24rQ1U5pOfptep-tuQb9zxDNZrkyD0ql1ln9nsq-MZkyglheQ0FoDQfzLmi6XIrU_o9-wefqb5sTIL5GrIRduSCP31yal-cytTU\",\"kty\":\"RSA\"}">>,
    {true,
    <<"{\"exp\":1459556927,\"imf.scope\":{\"wl_directUpdateRealm\":{\"exp\":1459556927,\"mandatory\":true},\"SubscribeServlet\":{\"exp\":1459556927,\"mandatory\":true},\"wl_authenticityRealm\":{\"exp\":1459556927,\"mandatory\":true},\"wl_remoteDisableRealm\":{\"exp\":1459556927,\"mandatory\":true},\"SampleAppRealm\":{\"exp\":1459556927,\"mandatory\":true},\"wl_antiXSRFRealm\":{\"exp\":1459556927,\"mandatory\":true},\"wl_deviceAutoProvisioningRealm\":{\"exp\":1459556927,\"mandatory\":true},\"wl_deviceNoProvisioningRealm\":{\"exp\":1459556927,\"mandatory\":true},\"wl_anonymousUserRealm\":{\"exp\":1459556927,\"mandatory\":true}},\"iss\":\"http:\\/\\/9.111.27.162:10080\\/worklight\\/authorization\\/v1\\/testtoken\",\"prn\":\"testClient401550315\"}">>,
    #jose_jws{
       alg = {jose_jws_alg_rsa_pkcs1_v1_5,
              {jose_jws_alg_rsa_pkcs1_v1_5,sha256}},
       b64 = undefined,sph = undefined,
       fields = Fields}} = jose_jwk:verify(AccessToken, Key),
    Fields =  #{<<"jpk">> => #{<<"alg">> => <<"RSA">>,
                               <<"exp">> => <<"AQAB">>,
                               <<"mod">> => <<"AJqdjLUmbBdYhd5FN6jAnbaOSBndcvehwjf6S8MYlBiYpEErMxCgVq4DFxVzzWSfaV3GuzbXO38b4JQIuvXk8OuIsK-m5p7Er5xuVFxSdjCMGT9LlL-OTUvHIGfYGB6MAxkGXozA6G2e-rKlvgFzTY_oBs0XT_CuijLMaRUz1eDGzqGEAoNVIuAozzHbKVlLlnruJrJ00tkixVUEGrUJ4CKd7bePvWrPOOXArNLGKp7O2jLon3uT24rQ1U5pOfptep-tuQb9zxDNZrkyD0ql1ln9nsq-MZkyglheQ0FoDQfzLmi6XIrU_o9-wefqb5sTIL5GrIRduSCP31yal-cytTU">>}},
    ok.
