## For every x in interval [0, 2^(40) - 1], x = x0 * B + x1, where
##  x0 = {0, ... B-1}, and x_1 = {0, ..., B-1}. i.e every pair of (x0, x1) reps
##  a number for x in the said interval.
##
## B^2 = 2^40, so x = x0 * B + x1 spans [0, 2^(40) - 1].
##

# Lookup for all possible h/g^(x1) (mod p) values
def build_table(
        mod_p: int, 
        target_h: int, 
        base_g: int,
        split_B: int
) -> dict[int, int]:

    # {x1 : h/g^(x1)}
    lookup: dict[int: int] = {}

    # We can express g^-1 => g^(p-2) mod p
    # Then by commutativity:
    # 1/g^(x1) => (g^(x1))^(-1) => (g^(x1))^(p-2) => (g^(p-2))^(x1)
    g_inverse = pow(base_g, mod_p - 2, mod_p)

    # LHS <- h * (g^(p-2))^(x1), where x1 = {0, 1, ..., 2^(20) - 1}
    LHS = target_h

    # x1 = 0, LHS0 = h * (g_inv)^(0)
    lookup[0] = target_h

    # x1 = 1, LHS1 = LHS0 * g_inv
    # x1 = 2, LHS2 = LHS1 * g_inv
    # x1 = 3, LHS3 = LHS2 * g_inv
    for x1 in range(1, split_B):
        LHS = target_h * g_inverse
        lookup[x1] = LHS

    return lookup



def d_log(
        mod_p: int,
        base_g: int,
        target_h: int,  # h = g^x
        split_B: int    # for x = x0 * B + x1
) -> int:


    return 0





def main():
    B = 1 << 20
    p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
    g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
    h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333

    print("hello")





if __name__ == "__main__":
    main()