package jwa

//GetAlgorithmName for an algorithm returns the jwt Header Parameter Values
//as described here: https://tools.ietf.org/html/rfc7518#section-3.1
func GetAlgorithmName(alg Algorithm) string {
	switch alg {
	case EC256:
		return ECP256Name
	case EC384:
		return ECP384Name
	case EC521:
		return ECP521Name
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
	case ECP256Name:
		return EC256
	case ECP384Name:
		return EC384
	case ECP521Name:
		return EC521
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
