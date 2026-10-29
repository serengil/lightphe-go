package lightphe

import (
	"encoding/json"
	"errors"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// ---------------------------------------------------------------------------
// Sending ciphertexts over network
// ---------------------------------------------------------------------------

// Serialize converts ciphertexts, proofs or messages of interactive protocols
// into json to send them to another party. Item is a Ciphertext, a Tensor, or
// any json serializable value having them, e.g. outputs of
// EncryptWithRangeProof, EncryptKNNQuery, EncryptUpdate or PartialDecrypt.
// Keys are never serialized, the receiver restores ciphertexts with its own
// public key. Ciphertexts and tensors are encoded in the format of the Python
// library, so the two libraries exchange them.
func (c *Cryptosystem) Serialize(item interface{}) ([]byte, error) {
	return json.Marshal(item)
}

// Deserialize restores ciphertexts, proofs or messages of interactive
// protocols serialized by another party into target, which must be a pointer,
// e.g. a **Ciphertext, a *[]*Ciphertext or a **EncryptedQuery. Ciphertexts
// are restored with the public key of this cryptosystem, and must belong to
// its algorithm.
func (c *Cryptosystem) Deserialize(data []byte, target interface{}) error {
	if err := json.Unmarshal(data, target); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return phe.InvalidCiphertextf("serialized data is not a valid json: %v", err)
		}
		return err
	}
	return c.Restore(target)
}

// Restore binds ciphertexts decoded with json.Unmarshal in target to the
// public key of this cryptosystem, e.g. when a ciphertext is a part of a
// request body decoded elsewhere. Deserialize calls it already.
func (c *Cryptosystem) Restore(target interface{}) error {
	return encrypted.Restore(target, c.publicUnboosted())
}
