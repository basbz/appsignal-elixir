defmodule Appsignal.TransmitterTest do
  use ExUnit.Case
  alias Appsignal.{Config, Transmitter}
  import AppsignalTest.Utils
  import ExUnit.CaptureLog

  setup do
    Application.put_env(:appsignal, :http_client, FakeHackney)

    on_exit(fn ->
      Application.delete_env(:appsignal, :http_client)
    end)
  end

  test "uses the default CA certificate" do
    path = Config.ca_file_path()
    hostname_match_fun = :public_key.pkix_verify_hostname_match_fun(:https)

    assert [
             _method,
             _url,
             _headers,
             _body,
             [
               ssl_options: [
                 verify: :verify_peer,
                 cacertfile: ^path,
                 depth: 2,
                 customize_hostname_check: [
                   match_fun: ^hostname_match_fun
                 ],
                 ciphers: _,
                 honor_cipher_order: :undefined
               ]
             ]
           ] = Transmitter.request(:get, "https://example.com")
  end

  test "uses the configured CA certificate" do
    path = "priv/cacert.pem"
    hostname_match_fun = :public_key.pkix_verify_hostname_match_fun(:https)

    with_config(%{ca_file_path: path}, fn ->
      assert [
               _method,
               _url,
               _headers,
               _body,
               [
                 ssl_options: [
                   verify: :verify_peer,
                   cacertfile: ^path,
                   depth: 2,
                   customize_hostname_check: [
                     match_fun: ^hostname_match_fun
                   ],
                   ciphers: _,
                   honor_cipher_order: :undefined
                 ]
               ]
             ] = Transmitter.request(:get, "https://example.com")
    end)
  end

  test "logs a warning when the CA certificate file does not exist" do
    path = "test/fixtures/does_not_exist.pem"

    with_config(%{ca_file_path: path}, fn ->
      assert capture_log(fn ->
               assert [_method, _url, _headers, _body, []] =
                        Transmitter.request(:get, "https://example.com")
             end) =~
               "[warn]  Ignoring non-existing or unreadable ca_file_path (test/fixtures/does_not_exist.pem): :enoent"
    end)
  end
end
