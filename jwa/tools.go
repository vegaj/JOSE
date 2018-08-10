package jwa

//GetAlgorithmName for an algorithm returns the jwt Header Parameter Values
//as described here: https://tools.ietf.org/html/rfc7518#section-3.1
func GetAlgorithmName(alg Algorithm) string {
	switch alg {
	case ES256:
		return ES256Name
	case ES384:
		return ES384Name
	case ES512:
		return ES512Name
	case RS256:
		return RS256Name
	case RS384:
		return RS384Name
	case RS512:
		return RS512Name
	case HS256:
		return HS256Name
	case HS384:
		return HS384Name
	case HS512:
		return HS512Name
	default:
		return ""
	}
}

//AlgorithmFromName returns the algorithm associated with the input algorithm name.
func AlgorithmFromName(name string) Algorithm {
	switch name {
	case ES256Name:
		return ES256
	case ES384Name:
		return ES384
	case ES512Name:
		return ES512
	case RS256Name:
		return RS256
	case RS384Name:
		return RS384
	case RS512Name:
		return RS512
	case HS256Name:
		return HS256
	case HS384Name:
		return HS384
	case HS512Name:
		return HS512
	default:
		return UNSUP
	}
}
