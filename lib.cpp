#include <blst.h>
#include <iostream>

int main() {
  // Generate a secret key
  blst_scalar sk;
  blst_keygen(nullptr, &sk);

  // Generate the corresponding public key
  blst_p1 pk;
  blst_sk_to_pk(&pk, &sk);

  // Sign a message
  const char* message = "Hello, world!";
  size_t message_len = std::strlen(message);
  blst_scalar msg_hash;
  blst_hash_to_scalar(&msg_hash, message, message_len);
  blst_p1 sig;
  blst_sign_pk(&sig, &sk, &pk, &msg_hash);

  // Verify the signature
  bool valid = blst_pk_in_g1(&pk) && blst_sig_verify_pk(&sig, &pk, &msg_hash);

  // Print the results
  std::cout << "Secret key: " << blst_bendian_from_scalar(&sk).hex_str() << std::endl;
  std::cout << "Public key: " << blst_bendian_from_p1_affine(&pk).hex_str() << std::endl;
  std::cout << "Signature: " << blst_bendian_from_p1_affine(&sig).hex_str() << std::endl;
  std::cout << "Signature valid: " << std::boolalpha << valid << std::endl;

  return 0;
}
