@files=[]

task :default do
  system("rake -T")
end

task :gen_certs do
  plaintext_path = "spec/fixtures/plaintext"
  encrypted_path = "spec/fixtures/encrypted"
  `openssl genrsa -out #{plaintext_path}/instance.key 4096`
  `openssl rsa -in #{plaintext_path}/instance.key -out #{encrypted_path}/instance.key -aes128 -traditional -passout pass:1234567890`
  `openssl req -new -x509 -key #{plaintext_path}/instance.key -out #{plaintext_path}/instance.crt -days 365 -subj "/CN=localhost"`
  `openssl req -new -x509 -key #{plaintext_path}/instance.key -out #{encrypted_path}/instance.crt -days 365 -subj "/CN=localhost"`
end

require "logstash/devutils/rake"
