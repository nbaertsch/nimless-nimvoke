import utils/nimjaStructs
import winim/lean
import utils/getpeb

type NINSTANCE = object
    peb*: NimjaPeb

var ninst* {.inject.}: NINSTANCE
