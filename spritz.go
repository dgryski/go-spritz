// Package spritz implements the Spritz stream-cipher
/*

http://people.csail.mit.edu/rivest/pubs/RS14.pdf

*/
package spritz

const N = 256

type cipher struct {
	i, j, k byte
	z       byte
	a       byte
	w       byte
	s       [N]byte
}

func (c *cipher) initializeState() {
	// reset
	*c = cipher{}

	c.w = 1

	for i := 0; i < N; i++ {
		c.s[i] = byte(i)
	}
}

func (c *cipher) absorb(I []byte) {

	for _, b := range I {
		c.absorbByte(b)
	}
}

func (c *cipher) absorbByte(b byte) {
	c.absorbNibble(b & 0x0f)
	c.absorbNibble((b & 0xf0) >> 4)
}

func (c *cipher) absorbNibble(x byte) {

	if c.a == N/2 {
		c.shuffle()
	}

	c.s[c.a], c.s[N/2+x] = c.s[N/2+x], c.s[c.a]
	c.a++
}

func (c *cipher) absorbStop() {

	if c.a == N/2 {
		c.shuffle()
	}

	c.a++
}

func (c *cipher) shuffle() {
	c.whip(2 * N)
	c.crush()
	c.whip(2 * N)
	c.crush()
	c.whip(2 * N)
	c.a = 0
}

func (c *cipher) whip(r int) {
	for v := 0; v < r; v++ {
		c.update()
	}

	c.w += 2
}

func (c *cipher) crush() {

	for v := 0; v < N/2; v++ {
		if c.s[v] > c.s[N-1-v] {
			c.s[v], c.s[N-1-v] = c.s[N-1-v], c.s[v]
		}
	}
}

func (c *cipher) squeeze(r int) []byte {

	if c.a > 0 {
		c.shuffle()
	}

	p := make([]byte, r)

	for v := 0; v < r; v++ {
		p[v] = c.drip()
	}

	return p
}

func (c *cipher) drip() byte {
	if c.a > 0 {
		c.shuffle()
	}

	c.update()

	return c.output()
}

func (c *cipher) update() {
	c.i = c.i + c.w
	c.j = c.k + c.s[c.j+c.s[c.i]]
	c.k = c.i + c.k + c.s[c.j]
	c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
}

func (c *cipher) output() byte {
	c.z = c.s[c.j+c.s[c.i+c.s[c.z+c.k]]]
	return c.z
}

func Encrypt(k, m []byte) []byte {

	var c cipher

	c.keySetup(k)

	ctxt := make([]byte, len(m))

	for i, x := range c.squeeze(len(ctxt)) {
		ctxt[i] = m[i] + x
	}

	return ctxt
}

func Decrypt(k, m []byte) []byte {

	var c cipher

	c.keySetup(k)

	ptxt := make([]byte, len(m))

	for i, x := range c.squeeze(len(ptxt)) {
		ptxt[i] = m[i] - x
	}

	return ptxt
}

func (c *cipher) keySetup(k []byte) {
	c.initializeState()
	c.absorb(k)
}
