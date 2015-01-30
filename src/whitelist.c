#include <string.h>
#include "repsheet.h"
#include "common.h"
#include "cidr.h"

#include "whitelist.h"

/**
 * @file whitelist.c
 * @author Aaron Bedra
 * @date 12/09/2014
 */

/**
 * Adds the actor to the Repsheet whitelist
 *
 * @param context the Redis connection
 * @param actor the actors user data or ip address
 * @param type IP or USER
 * @reason string to describe the reason for whitelisting
 *
 * @returns an integer result
 */
int whitelist_actor(redisContext *context, const char *actor, int type, const char *reason)
{
  redisReply *reply;

  switch(type) {
  case IP:
    return set_list(context, actor, "ip", "whitelisted", reason);
    break;
  case USER:
    return set_list(context, actor, "users", "whitelisted", reason);
    break;
  case BLOCK:
    return set_list(context, actor, "cidr", "whitelisted", reason);
    break;
  default:
    return UNSUPPORTED;
    break;
  }
}

/**
 * Checks to see if an ip is on the Repsheet whitelist
 *
 * @param context the Redis connection
 * @param actor the IP address of the actor
 * @param reason returns the reason for whitelisting.
 *
 * @returns TRUE if yes, FALSE if no, DISCONNECTED if error
 */
int is_ip_whitelisted(redisContext *context, const char *actor, char *reason)
{
  redisReply *ip = redisCommand(context, "GET %s:repsheet:ip:whitelisted", actor);
  if (ip) {
    if (ip->type == REDIS_REPLY_STRING) {
      populate_reason(ip, reason);
      freeReplyObject(ip);
      return TRUE;
    } else {
      freeReplyObject(ip);
    }
  } else {
    return DISCONNECTED;
  }

  redisReply *whitelist = redisCommand(context, "KEYS *:repsheet:cidr:whitelisted");
  if (whitelist) {
    if (whitelist->type == REDIS_REPLY_ARRAY) {
      int i;
      redisReply *value;
      char *block;
      for(i = 0; i < whitelist->elements; i++) {
        block = strtok(whitelist->element[i]->str, ":");
        if (cidr_contains(block, actor) > 0) {
          value = redisCommand(context, "GET %s:repsheet:cidr:whitelisted", block);
          if (value) {
            populate_reason(value, reason);
            freeReplyObject(value);
          }
          freeReplyObject(whitelist);
          return TRUE;
        }
      }
    } else{
      freeReplyObject(whitelist);
    }
  } else {
    return DISCONNECTED;
  }

  return FALSE;
}

/**
 * Checks to see if a user is on the Repsheet whitelist
 *
 * @param context the Redis connection
 * @param actor the user
 * @param reason returns the reason for whitelisting.
 *
 * @returns TRUE if yes, FALSE if no, DISCONNECTED if error
 */
int is_user_whitelisted(redisContext *context, const char *actor, char *reason)
{
  redisReply *reply;

  reply = redisCommand(context, "GET %s:repsheet:users:whitelisted", actor);
  if (reply) {
    if (reply->type == REDIS_REPLY_STRING) {
      populate_reason(reply, reason);
      freeReplyObject(reply);
      return TRUE;
    } else {
      freeReplyObject(reply);
      return FALSE;
    }
  } else {
    return DISCONNECTED;
  }
}

/**
 * Looks up the country to see if it is whitelisted.
 *
 * @param context the Redis connection
 * @param country_code the 2 digit ISO country code
 *
 * @returns an integer response
 */
int is_country_whitelisted(redisContext *context, const char *country_code)
{
  redisReply *reply;
  reply = redisCommand(context, "SISMEMBER repsheet:countries:whitelisted %s", country_code);
  if (reply) {
    if (reply->type == REDIS_REPLY_INTEGER) {
      freeReplyObject(reply);
      return reply->integer;
    } else {
      freeReplyObject(reply);
      return NIL;
    }
  } else {
    return DISCONNECTED;
  }
}
