#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "repsheet.h"
#include "cidr.h"

/**
 * @file cidr.c
 * @author Aaron Bedra
 * @date 10/09/2014
 */

int _string_to_cidr(CIDR *cidr, char *block);

int block_to_range( char *block, range *range )
{
  if (block == NULL) {
    return NIL;
  }

  CIDR cidr;
  int result = _string_to_cidr(&cidr, block);
  if (result == BAD_ADDRESS || result == BAD_CIDR_BLOCK) {
    return result;
  }

  range->lower = cidr.address;
  range->upper = range->lower + (1 <<  (32 - cidr.mask)) - 1;

  if (cidr.address == BAD_ADDRESS) {
    return BAD_ADDRESS;
  }
  return 1;
}

/**
 * Test an IP to see if it is contained in the CIDR block
 *
 * @param block the CIDR block string
 * @param address the IP address string
 *
 * @returns 1 if in the block, 0 if not
 */
int cidr_contains(char *block, int ip)
{
  range range;
  if (ip == BAD_ADDRESS)
    {
      return BAD_ADDRESS;
    }
  int rc =  block_to_range(block, &range);
  if (rc <= 0) {
    return rc;
  }
  return address_in_range(&range, ip);
}

int address_in_range(range *r, int ip)
{
  return ((r->lower <= ip) && (ip <= r->upper));
}

int _string_to_cidr(CIDR *cidr, char *block)
{
  CIDR tmpCIDR;
  char *cursor = block;
  int tmp_cursor = 0;
  tmpCIDR.mask = -1;
  tmpCIDR.address = -1;
  tmpCIDR.address_string[0] = '\0';

  // copy the address portion into the tmpCIDR while we look for the '/'
  // separator
  while(*cursor != '/' && *cursor != '\0' &&
    cursor - block < MAX_BLOCK_ADDRESS_STRING_SIZE)
  {
    tmpCIDR.address_string[tmp_cursor] = *cursor;
    cursor++;
    tmp_cursor++;
  }

  // if we found the '/' separator, make sure the address string is long
  // enough and not too long
  if (*cursor == '/') {
    tmpCIDR.address_string[tmp_cursor] = '\0';
    if (tmp_cursor < 7 || tmp_cursor > 16) { // 15?
      return BAD_CIDR_BLOCK;
    }

    // now do the mask
    cursor++; // move past the '/'
    tmpCIDR.mask = strtol(cursor, 0, 10);
    if (tmpCIDR.mask < 0 || tmpCIDR.mask > 32 || (tmpCIDR.mask == 0 && *cursor != '0')) {
      return BAD_CIDR_BLOCK;
    }

    // now convert the address
    tmpCIDR.address = ip_address_to_integer(tmpCIDR.address_string);
    if (tmpCIDR.address == BAD_ADDRESS) {
      return BAD_ADDRESS;
    }
  }
  else {
    return BAD_CIDR_BLOCK;
  }

  memcpy(cidr, &tmpCIDR, sizeof(CIDR));
  return LIBREPSHEET_OK;
}

//TODO: make this a LONG, because it can give negative numbers.
int ip_address_to_integer(const char *  address)
{
  char tmp_string[MAX_BLOCK_ADDRESS_STRING_SIZE];
  char *cursor = tmp_string;
  long octets[4];
  int octet_number = 0;

  // make sure we're not overflowing any buffers
  strncpy(tmp_string, address, MAX_BLOCK_ADDRESS_STRING_SIZE);
  tmp_string[MAX_BLOCK_ADDRESS_STRING_SIZE - 1] = '\0';

  // walk through the string parsing and verifying the octets one at a time
  while (octet_number < 4){
    char *cursor2 = cursor;

    // walk cursor2 forward up to 3 char to the end of this octet
    for (; *cursor2 != '.' && *cursor2 != '\0' &&
      cursor2 - cursor < 4; cursor2++) {}

    // if we found a delimiter and there's at least one char in the octet
    // we can try to convert the octet
    if ((*cursor2 == '.' || *cursor2 == '\0') && cursor2 - cursor > 0){
      *cursor2 = '\0';
      octets[octet_number] = strtol(cursor, 0, 10);

      // if the octet value is between 0 and 255
      if ((octets[octet_number] & ~0xFF) == 0){
        octet_number++;
        cursor = cursor2 + 1;
      }
      else {
        return BAD_ADDRESS;
      }
    }
    else {
      return BAD_ADDRESS;
    }
  }

  int ip_integer = (octets[0] << 24)
    | (octets[1] << 16)
    | (octets[2] << 8)
    | octets[3];

  return ip_integer;
}
