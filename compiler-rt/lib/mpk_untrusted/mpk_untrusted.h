#ifndef MPKUNTRUSTED_H
#define MPKUNTRUSTED_H

extern "C" {

__attribute__((visibility("default"))) static void mpk_untrusted_constructor();

__attribute__((visibility("default"))) static void __attribute__((constructor))

mpk_untrusted();
}

#endif
