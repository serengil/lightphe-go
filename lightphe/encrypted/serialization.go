package encrypted

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/catalanofiore"
)

// Ciphertexts and encrypted tensors marshal to the json format of the Python
// library, so the two libraries exchange them. Keys are never serialized, the
// receiver restores ciphertexts with its own public key: json.Unmarshal leaves
// them unbound, and Restore binds them to the receiver's cryptosystem.

// Tag is the key marking an encoded object that json cannot represent
// natively.
const Tag = "__lightphe__"

// SerializationVersion is the version of the encoding, increased if it
// changes in a backward incompatible way.
const SerializationVersion = 1

// kinds of encoded objects
const (
	kindCiphertext    = "ciphertext"
	kindCatalanoFiore = "catalano-fiore"
	kindTensor        = "tensor"
	kindFraction      = "fraction"
	kindPoint         = "point"
	kindTuple         = "tuple"
	kindFloat         = "float"
)

// ErrUnbound reports a ciphertext decoded with json.Unmarshal but not bound to
// a cryptosystem yet.
var ErrUnbound = fmt.Errorf("encrypted: ciphertext is not bound to a cryptosystem, "+
	"restore it with Cryptosystem.Restore or decode it with Cryptosystem.Deserialize: %w", phe.ErrInvalidCiphertext)

var errInvalidContent = phe.InvalidCiphertextf("ciphertext must consist of integers, or tuples and lists of them")

// infinity is the encoded coordinate of the point at infinity, which is
// (inf, inf) in the Python library.
var infinity = map[string]interface{}{Tag: kindFloat, "value": "inf"}

// pendingCiphertext is a decoded ciphertext waiting to be bound to the
// receiver's cryptosystem.
type pendingCiphertext struct {
	kind      string
	algorithm phe.Algorithm

	// value of a ciphertext
	value phe.Value

	// components of a Catalano-Fiore ciphertext
	a           *big.Int
	beta, alpha *pendingCiphertext
	pairs       [][2]*pendingCiphertext
}

// pendingTensor is a decoded encrypted tensor waiting to be bound to the
// receiver's cryptosystem.
type pendingTensor struct {
	algorithm phe.Algorithm
	precision int
	fractions []Fraction
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// MarshalJSON implements json.Marshaler. Keys are not included, the receiver
// restores the ciphertext with its own public key.
func (c *Ciphertext) MarshalJSON() ([]byte, error) {
	if c.cs == nil {
		return nil, ErrUnbound
	}
	doc, err := encodeCiphertext(c.cs, c.Value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// MarshalJSON implements json.Marshaler. Keys are not included, the receiver
// restores the tensor with its own public key.
func (t *Tensor) MarshalJSON() ([]byte, error) {
	if t.cs == nil {
		return nil, ErrUnbound
	}
	alg := t.cs.Algorithm()
	fractions := make([]interface{}, len(t.Fractions))
	for i, f := range t.Fractions {
		fraction := map[string]interface{}{Tag: kindFraction, "sign": f.Sign}
		for name, v := range map[string]phe.Value{"dividend": f.Dividend, "abs_dividend": f.AbsDividend, "divisor": f.Divisor} {
			encoded, err := encodeValue(alg, v)
			if err != nil {
				return nil, err
			}
			fraction[name] = encoded
		}
		fractions[i] = fraction
	}
	return json.Marshal(map[string]interface{}{
		Tag:              kindTensor,
		"version":        SerializationVersion,
		"algorithm_name": string(alg),
		"precision":      t.precision,
		"fractions":      fractions,
	})
}

func encodeCiphertext(cs phe.Homomorphic, value phe.Value) (map[string]interface{}, error) {
	alg := cs.Algorithm()
	cf, boosted := cs.(*catalanofiore.Cryptosystem)
	if !boosted {
		encoded, err := encodeValue(alg, value)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			Tag:              kindCiphertext,
			"version":        SerializationVersion,
			"algorithm_name": string(alg),
			"value":          encoded,
		}, nil
	}

	parts, err := catalanofiore.Split(value)
	if err != nil {
		return nil, err
	}
	inner := func(v phe.Value) (map[string]interface{}, error) { return encodeCiphertext(cf.Inner(), v) }
	doc := map[string]interface{}{
		Tag:              kindCatalanoFiore,
		"version":        SerializationVersion,
		"algorithm_name": string(alg),
		"a":              nil,
		"beta":           nil,
		"alpha":          nil,
		"pairs":          []interface{}{},
	}
	if !parts.Multiplied {
		doc["a"] = parts.A
		doc["beta"], err = inner(parts.Beta)
		return doc, err
	}
	if doc["alpha"], err = inner(parts.Alpha); err != nil {
		return nil, err
	}
	pairs := make([]interface{}, len(parts.Pairs))
	for i, pair := range parts.Pairs {
		beta1, err := inner(pair[0])
		if err != nil {
			return nil, err
		}
		beta2, err := inner(pair[1])
		if err != nil {
			return nil, err
		}
		pairs[i] = []interface{}{beta1, beta2}
	}
	doc["pairs"] = pairs
	return doc, nil
}

// encodeValue converts a ciphertext value into the shapes of the Python
// library: tuples, except lists of Goldwasser-Micali and Sander-Young-Yung,
// points of Boneh-Goh-Nissim, and coordinate tuples of other curve points and
// of F_{p^2} elements.
func encodeValue(alg phe.Algorithm, v phe.Value) (interface{}, error) {
	switch t := v.(type) {
	case phe.Int:
		return t.V, nil
	case phe.Tuple:
		items := make([]interface{}, len(t.Items))
		for i, item := range t.Items {
			encoded, err := encodeValue(alg, item)
			if err != nil {
				return nil, err
			}
			items[i] = encoded
		}
		if alg == phe.GoldwasserMicali || alg == phe.SanderYoungYung {
			return items, nil
		}
		return map[string]interface{}{Tag: kindTuple, "items": items}, nil
	case phe.Point:
		var x, y interface{} = t.X, t.Y
		if t.Infinity {
			x, y = infinity, infinity
		}
		if alg == phe.BonehGohNissim {
			return map[string]interface{}{Tag: kindPoint, "x": x, "y": y}, nil
		}
		return map[string]interface{}{Tag: kindTuple, "items": []interface{}{x, y}}, nil
	case phe.FP2:
		return map[string]interface{}{Tag: kindTuple, "items": []interface{}{t.A, t.B}}, nil
	}
	return nil, phe.InvalidCiphertextf("encrypted: cannot serialize a ciphertext value of type %T", v)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// UnmarshalJSON implements json.Unmarshaler. The decoded ciphertext is not
// bound to a cryptosystem until Restore binds it.
func (c *Ciphertext) UnmarshalJSON(data []byte) error {
	doc, err := decodeDocument(data)
	if err != nil {
		return err
	}
	p, err := decodeCiphertext(doc, true)
	if err != nil {
		return err
	}
	*c = Ciphertext{pending: p}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler. The decoded tensor is not bound
// to a cryptosystem until Restore binds it.
func (t *Tensor) UnmarshalJSON(data []byte) error {
	doc, err := decodeDocument(data)
	if err != nil {
		return err
	}
	if err := checkHeader(doc, kindTensor); err != nil {
		return err
	}
	precision, err := intField(doc, "precision")
	if err != nil {
		return err
	}
	items, ok := doc["fractions"].([]interface{})
	if !ok {
		return phe.InvalidCiphertextf("field fractions of serialized tensor must be a list")
	}
	fractions := make([]Fraction, len(items))
	for i, item := range items {
		if fractions[i], err = decodeFraction(item); err != nil {
			return err
		}
	}
	*t = Tensor{pending: &pendingTensor{
		algorithm: phe.Algorithm(doc["algorithm_name"].(string)),
		precision: precision,
		fractions: fractions,
	}}
	return nil
}

// decodeDocument parses a json object, keeping numbers exact.
func decodeDocument(data []byte) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc map[string]interface{}
	if err := decoder.Decode(&doc); err != nil || doc == nil {
		return nil, phe.InvalidCiphertextf("serialized ciphertext must be a json object")
	}
	return doc, nil
}

// checkHeader checks the kind, version and algorithm of an encoded object.
func checkHeader(doc map[string]interface{}, kind string) error {
	if doc[Tag] != kind {
		return phe.InvalidCiphertextf("serialized object is %v, want %s", doc[Tag], kind)
	}
	if version, ok := doc["version"].(json.Number); !ok || version.String() != fmt.Sprint(SerializationVersion) {
		return phe.InvalidCiphertextf("unsupported serialization version %v, expected %d", doc["version"], SerializationVersion)
	}
	if _, ok := doc["algorithm_name"].(string); !ok {
		return phe.InvalidCiphertextf("field algorithm_name of serialized %s must be a string", kind)
	}
	return nil
}

// decodeCiphertext decodes a ciphertext, or a Catalano-Fiore ciphertext if
// allowed.
func decodeCiphertext(doc map[string]interface{}, allowBoosted bool) (*pendingCiphertext, error) {
	kind := doc[Tag]
	if kind == kindCatalanoFiore && allowBoosted {
		return decodeCatalanoFiore(doc)
	}
	if err := checkHeader(doc, kindCiphertext); err != nil {
		return nil, err
	}
	value, err := decodeValue(doc["value"])
	if err != nil {
		return nil, err
	}
	return &pendingCiphertext{
		kind:      kindCiphertext,
		algorithm: phe.Algorithm(doc["algorithm_name"].(string)),
		value:     value,
	}, nil
}

func decodeCatalanoFiore(doc map[string]interface{}) (*pendingCiphertext, error) {
	if err := checkHeader(doc, kindCatalanoFiore); err != nil {
		return nil, err
	}
	p := &pendingCiphertext{kind: kindCatalanoFiore, algorithm: phe.Algorithm(doc["algorithm_name"].(string))}

	// nested ciphertexts must be ciphertexts of the underlying cryptosystem
	nested := func(item interface{}) (*pendingCiphertext, error) {
		if item == nil {
			return nil, nil
		}
		inner, ok := item.(map[string]interface{})
		if !ok || inner[Tag] != kindCiphertext {
			return nil, phe.InvalidCiphertextf("Catalano-Fiore ciphertext must consist of ciphertexts")
		}
		return decodeCiphertext(inner, false)
	}

	var err error
	if a := doc["a"]; a != nil {
		if p.a, err = decodeInt(a); err != nil {
			return nil, phe.InvalidCiphertextf("a of a Catalano-Fiore ciphertext must be an integer")
		}
	}
	if p.beta, err = nested(doc["beta"]); err != nil {
		return nil, err
	}
	if p.alpha, err = nested(doc["alpha"]); err != nil {
		return nil, err
	}
	pairs, ok := doc["pairs"].([]interface{})
	if !ok {
		return nil, phe.InvalidCiphertextf("field pairs of serialized catalano-fiore must be a list")
	}
	for _, item := range pairs {
		pair, ok := item.([]interface{})
		if !ok || len(pair) != 2 {
			return nil, phe.InvalidCiphertextf("pairs of a Catalano-Fiore ciphertext must have 2 ciphertexts")
		}
		var decoded [2]*pendingCiphertext
		for i := range pair {
			if decoded[i], err = nested(pair[i]); err != nil {
				return nil, err
			}
			if decoded[i] == nil {
				return nil, phe.InvalidCiphertextf("pairs of a Catalano-Fiore ciphertext must have ciphertexts")
			}
		}
		p.pairs = append(p.pairs, decoded)
	}
	return p, nil
}

func decodeFraction(item interface{}) (Fraction, error) {
	doc, ok := item.(map[string]interface{})
	if !ok || doc[Tag] != kindFraction {
		return Fraction{}, phe.InvalidCiphertextf("items of an encrypted tensor must be fractions")
	}
	sign, err := intField(doc, "sign")
	if err != nil {
		return Fraction{}, err
	}
	if sign != 1 && sign != -1 {
		return Fraction{}, phe.InvalidCiphertextf("sign of a fraction must be 1 or -1")
	}
	f := Fraction{Sign: sign}
	for _, field := range []struct {
		name   string
		target *phe.Value
	}{{"dividend", &f.Dividend}, {"abs_dividend", &f.AbsDividend}, {"divisor", &f.Divisor}} {
		if *field.target, err = decodeValue(doc[field.name]); err != nil {
			return Fraction{}, err
		}
	}
	return f, nil
}

// decodeValue restores a ciphertext value, which must consist of integers,
// tuples and lists of them, or elliptic curve points. Points are checked to be
// on the curve when they are bound to the receiver's cryptosystem.
func decodeValue(item interface{}) (phe.Value, error) {
	switch t := item.(type) {
	case json.Number:
		v, err := decodeInt(t)
		if err != nil {
			return nil, err
		}
		return phe.Int{V: v}, nil
	case []interface{}:
		return decodeItems(t)
	case map[string]interface{}:
		switch t[Tag] {
		case kindTuple:
			items, ok := t["items"].([]interface{})
			if !ok {
				return nil, errInvalidContent
			}
			if len(items) == 2 && isInfinity(items[0]) && isInfinity(items[1]) {
				return phe.InfinityPoint(), nil
			}
			return decodeItems(items)
		case kindPoint:
			if isInfinity(t["x"]) && isInfinity(t["y"]) {
				return phe.InfinityPoint(), nil
			}
			x, errX := decodeInt(t["x"])
			y, errY := decodeInt(t["y"])
			if errX != nil || errY != nil {
				return nil, phe.InvalidCiphertextf("coordinates of an elliptic curve point must be integers")
			}
			return phe.Point{X: x, Y: y}, nil
		}
	}
	return nil, errInvalidContent
}

func decodeItems(items []interface{}) (phe.Value, error) {
	values := make([]phe.Value, len(items))
	for i, item := range items {
		v, err := decodeValue(item)
		if err != nil {
			return nil, err
		}
		values[i] = v
	}
	return phe.Tuple{Items: values}, nil
}

func decodeInt(item interface{}) (*big.Int, error) {
	n, ok := item.(json.Number)
	if !ok {
		return nil, errInvalidContent
	}
	v, ok := new(big.Int).SetString(n.String(), 10)
	if !ok {
		return nil, errInvalidContent
	}
	return v, nil
}

func intField(doc map[string]interface{}, name string) (int, error) {
	n, ok := doc[name].(json.Number)
	if ok {
		if v, err := n.Int64(); err == nil {
			return int(v), nil
		}
	}
	return 0, phe.InvalidCiphertextf("field %s of serialized %v must be an integer", name, doc[Tag])
}

func isInfinity(item interface{}) bool {
	doc, ok := item.(map[string]interface{})
	return ok && doc[Tag] == kindFloat && doc["value"] == "inf"
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

// Restore binds every ciphertext and encrypted tensor decoded with
// json.Unmarshal in target to cs, which is the receiver's public cryptosystem
// without the Catalano-Fiore transform. Catalano-Fiore ciphertexts are bound
// to the transform wrapping cs. Ciphertext values elsewhere in target, e.g. in
// range proofs or partial decryptions, are restored as points where the
// algorithm needs them. Restore checks that ciphertexts belong to the
// algorithm of cs, and that points are on its curve.
func Restore(target interface{}, cs phe.Homomorphic) error {
	if cs == nil {
		return fmt.Errorf("encrypted: restoring needs a cryptosystem")
	}
	r := &restorer{cs: cs, visited: map[uintptr]bool{}}
	if e, ok := cs.(interface{ ECC() *ecc.ECC }); ok {
		r.curve = e.ECC().Curve()
	}
	return r.walk(reflect.ValueOf(target))
}

type restorer struct {
	cs    phe.Homomorphic
	curve ecc.Curve

	// Catalano-Fiore transform wrapping cs, built on first use
	boosted *catalanofiore.Cryptosystem

	visited map[uintptr]bool
}

var valueType = reflect.TypeOf((*phe.Value)(nil)).Elem()

func (r *restorer) walk(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		switch p := v.Interface().(type) {
		case *Ciphertext:
			return r.ciphertext(p)
		case *Tensor:
			return r.tensor(p)
		}
		if r.visited[v.Pointer()] {
			return nil
		}
		r.visited[v.Pointer()] = true
		return r.walk(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		if v.Type() == valueType {
			shaped, err := r.shape(v.Elem().Interface().(phe.Value))
			if err != nil {
				return err
			}
			if v.CanSet() {
				v.Set(reflect.ValueOf(shaped))
			}
			return nil
		}
		return r.walk(v.Elem())
	case reflect.Struct:
		if v.CanAddr() {
			switch p := v.Addr().Interface().(type) {
			case *Ciphertext:
				return r.ciphertext(p)
			case *Tensor:
				return r.tensor(p)
			}
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				if err := r.walk(v.Field(i)); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := r.walk(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		// map values are not addressable, so restore a copy and store it back
		iter := v.MapRange()
		for iter.Next() {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(iter.Value())
			if err := r.walk(elem); err != nil {
				return err
			}
			v.SetMapIndex(iter.Key(), elem)
		}
	}
	return nil
}

func (r *restorer) ciphertext(c *Ciphertext) error {
	if c.pending == nil {
		return nil
	}
	cs, value, err := r.restore(c.pending)
	if err != nil {
		return err
	}
	*c = Ciphertext{cs: cs, Value: value}
	return nil
}

func (r *restorer) tensor(t *Tensor) error {
	p := t.pending
	if p == nil {
		return nil
	}
	if err := r.checkAlgorithm(kindTensor, p.algorithm); err != nil {
		return err
	}
	fractions := make([]Fraction, len(p.fractions))
	for i, f := range p.fractions {
		fractions[i] = Fraction{Sign: f.Sign}
		for _, field := range []struct{ source, target *phe.Value }{
			{&f.Dividend, &fractions[i].Dividend},
			{&f.AbsDividend, &fractions[i].AbsDividend},
			{&f.Divisor, &fractions[i].Divisor},
		} {
			shaped, err := r.shape(*field.source)
			if err != nil {
				return err
			}
			*field.target = shaped
		}
	}
	*t = Tensor{Fractions: fractions, cs: r.cs, precision: p.precision}
	return nil
}

func (r *restorer) checkAlgorithm(kind string, alg phe.Algorithm) error {
	if alg != r.cs.Algorithm() {
		return phe.InvalidCiphertextf("serialized %s belongs to %s, but this cryptosystem is %s", kind, alg, r.cs.Algorithm())
	}
	return nil
}

func (r *restorer) restore(p *pendingCiphertext) (phe.Homomorphic, phe.Value, error) {
	if err := r.checkAlgorithm(p.kind, p.algorithm); err != nil {
		return nil, nil, err
	}
	if p.kind == kindCiphertext {
		value, err := r.shape(p.value)
		return r.cs, value, err
	}

	if r.boosted == nil {
		boosted, err := catalanofiore.New(r.cs)
		if err != nil {
			return nil, nil, err
		}
		r.boosted = boosted
	}
	inner := func(p *pendingCiphertext) (phe.Value, error) {
		_, value, err := r.restore(p)
		return value, err
	}

	if p.alpha == nil {
		modulo := r.boosted.PlaintextModulo()
		if p.a == nil || p.a.Sign() < 0 || p.a.Cmp(modulo) >= 0 {
			return nil, nil, phe.InvalidCiphertextf("a of a Catalano-Fiore ciphertext must be in [0, %s)", modulo)
		}
		if p.beta == nil || len(p.pairs) > 0 {
			return nil, nil, phe.InvalidCiphertextf("non-multiplied Catalano-Fiore ciphertext must have a and beta only")
		}
		beta, err := inner(p.beta)
		if err != nil {
			return nil, nil, err
		}
		return r.boosted, catalanofiore.Join(catalanofiore.Parts{A: p.a, Beta: beta}), nil
	}

	if p.a != nil || p.beta != nil {
		return nil, nil, phe.InvalidCiphertextf("multiplied Catalano-Fiore ciphertext must have alpha and pairs only")
	}
	alpha, err := inner(p.alpha)
	if err != nil {
		return nil, nil, err
	}
	pairs := make([][2]phe.Value, len(p.pairs))
	for i, pair := range p.pairs {
		for j := range pair {
			if pairs[i][j], err = inner(pair[j]); err != nil {
				return nil, nil, err
			}
		}
	}
	return r.boosted, catalanofiore.Join(catalanofiore.Parts{Multiplied: true, Alpha: alpha, Pairs: pairs}), nil
}

// shape turns coordinate tuples into the curve points and F_{p^2} elements
// the algorithm uses, and checks that every point is on the curve.
func (r *restorer) shape(v phe.Value) (phe.Value, error) {
	switch r.cs.Algorithm() {
	case phe.EllipticCurveElGamal:
		// (c1, c2)
		if t, ok := v.(phe.Tuple); ok && t.Len() == 2 {
			v = phe.Tuple{Items: []phe.Value{toPoint(t.Items[0]), toPoint(t.Items[1])}}
		}
	case phe.BonehGohNissim:
		// a point, or an element of F_{p^2} after multiplication
		v = toFP2(v)
	case phe.FreemanBonehGohNissim:
		// 3 points, or 9 elements of F_{p^2} after multiplication
		if t, ok := v.(phe.Tuple); ok && (t.Len() == 3 || t.Len() == 9) {
			items := make([]phe.Value, t.Len())
			for i, item := range t.Items {
				if t.Len() == 3 {
					items[i] = toPoint(item)
				} else {
					items[i] = toFP2(item)
				}
			}
			v = phe.Tuple{Items: items}
		}
	}
	return v, r.checkPoints(v)
}

func (r *restorer) checkPoints(v phe.Value) error {
	switch t := v.(type) {
	case phe.Tuple:
		for _, item := range t.Items {
			if err := r.checkPoints(item); err != nil {
				return err
			}
		}
	case phe.Point:
		if r.curve == nil {
			return phe.InvalidCiphertextf("%s ciphertexts are not elliptic curve points", r.cs.Algorithm())
		}
		if t.Infinity {
			return nil
		}
		if _, err := ecc.NewPoint(r.curve, t.X, t.Y); err != nil {
			return phe.InvalidCiphertextf("serialized point is not on the curve")
		}
	}
	return nil
}

// toPoint turns a pair of integer coordinates into a point.
func toPoint(v phe.Value) phe.Value {
	if t, ok := v.(phe.Tuple); ok && t.Len() == 2 {
		if xy, err := t.Ints(); err == nil {
			return phe.Point{X: xy[0], Y: xy[1]}
		}
	}
	return v
}

// toFP2 turns a pair of integers into an element of F_{p^2}.
func toFP2(v phe.Value) phe.Value {
	if t, ok := v.(phe.Tuple); ok && t.Len() == 2 {
		if ab, err := t.Ints(); err == nil {
			return phe.FP2{A: ab[0], B: ab[1]}
		}
	}
	return v
}
