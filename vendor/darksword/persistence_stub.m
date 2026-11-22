//  Vendored stub for lara persistence.m: we do not transfer kread/kwrite
//  primitives into launchd. Every app launch re-runs the exploit; the
//  DarkSword socket primitives are repeatable per boot, so persistence
//  (and its TaskRop/mig machinery) is intentionally not vendored.
#import "persistence.h"
bool transfer_krw_to_launchd(void) { return false; }
bool recover_krw_primitives(void) { return false; }
