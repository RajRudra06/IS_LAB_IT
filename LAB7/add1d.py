# benchmark_phe.py
import time
from add1a import generate_keypair as eg_gen, encrypt as eg_enc, decrypt as eg_dec, homomorphic_multiply as eg_mul
from add1b import generate_paillier, paillier_encrypt, paillier_decrypt, homomorphic_add

def bench_paillier(pub, priv, messages, runs=50):
    t_enc = t_dec = t_hom = 0.0
    for _ in range(runs):
        m1, m2 = messages
        s = time.perf_counter()
        c1 = paillier_encrypt(pub, m1)
        t_enc += time.perf_counter() - s
        s = time.perf_counter()
        c2 = paillier_encrypt(pub, m2)
        t_enc += time.perf_counter() - s
        s = time.perf_counter()
        c_sum = homomorphic_add(c1, c2, pub)
        t_hom += time.perf_counter() - s
        s = time.perf_counter()
        _ = paillier_decrypt(pub, priv, c_sum)
        t_dec += time.perf_counter() - s
    return t_enc/runs, t_hom/runs, t_dec/runs

def bench_elgamal(pub, priv, messages, runs=50):
    t_enc = t_dec = t_hom = 0.0
    for _ in range(runs):
        m1, m2 = messages
        s = time.perf_counter()
        c1 = eg_enc(pub, m1)
        t_enc += time.perf_counter() - s
        s = time.perf_counter()
        c2 = eg_enc(pub, m2)
        t_enc += time.perf_counter() - s
        s = time.perf_counter()
        c_prod = eg_mul(c1, c2, pub)
        t_hom += time.perf_counter() - s
        s = time.perf_counter()
        _ = eg_dec(pub, priv, c_prod)
        t_dec += time.perf_counter() - s
    return t_enc/runs, t_hom/runs, t_dec/runs

if __name__ == "__main__":
    # Paillier
    pa_pub, pa_priv = generate_paillier(bit_length=512)
    # ElGamal
    eg_pub, eg_priv = eg_gen(bits=256)
    msgs = (15, 25)
    p_enc, p_hom, p_dec = bench_paillier(pa_pub, pa_priv, msgs, runs=30)
    e_enc, e_hom, e_dec = bench_elgamal(eg_pub, eg_priv, msgs, runs=30)
    print("Paillier avg times (s): encrypt, hom-add, decrypt:", p_enc, p_hom, p_dec)
    print("ElGamal avg times (s): encrypt, hom-mul, decrypt:", e_enc, e_hom, e_dec)
