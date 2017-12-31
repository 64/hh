#pragma once

// For some reason the cashpack header doesn't have include guards, and
// it doesn't include the standard library headers that it requires. So
// I wrote this quick wrapper to get around those two issues.

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include <hpack.h>
