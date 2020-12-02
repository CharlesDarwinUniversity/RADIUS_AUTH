################################################################################
#
# RADIUS_UTIL - Version 1.1.0 - 2020-12-01 ( formerly known as RADIUS_AUTH )
#
################################################################################
#
# Procedures used to manipulate RADIUS packets with support
# for Authenticator validation as well as Message-Authenticator.
#
# Tested on BIG-IP LTM 14.1.2
#
# Since name change:
#   Added client_addr params for SERVER_DATA on version 14.1.2
#   Added support for accounting packets
#
# Supported RADIUS codes:
# 1:  Access-Request
# 2:  Access-Accept
# 3:  Access-Reject
# 4:  Accounting-Request
# 5:  Accounting-Response
# 11: Access-Challenge
#
# Installation: Create this irule as /Common/RADIUS_UTIL
#
# Usage:
# Generally, when CLIENT_ACCEPTED call "parse_packet" to get information about
# an Access-Request from a RADIUS client. The AVP array can then be manipulated
# and a new packet generated in order to either replace the payload sent to the
# server or drop the packet and respond directly.
#
# AVP array now uses a floating point multiple value index. The type code is
# the integer component, the value after the decimal point is the sequence in
# which it was read from the payload. In this manner, you could use for example
# [array get AVP 18.*] to list all Reply-Message attributes in case there are
# multiples. If you only care about the first instance of an attribute,
# remember to use the float values like AVP(18.0) as AVP(18) would not be set.
#
# When working with Message-Authenticator, a key must be provided. Failure to
# validate a Message-Authenticator will result in an error.
#
# There is no need to supply the Request Authenticator via the optional req_auth
# parameter as long as the Access-Request went through parse_packet and you
# generate a response before the timeout removes the entry from the table.
#
# You can use RADIUS_UTIL to some extent in conjunction with RADIUS::avp. Avoid
# using RADIUS::avp to change values on packets that use Message-Authenticator.
#
# Shortcomings:
# This library is concerned mostly with validating the packet structure.
# In terms of RFC compliance, this library doesn't do any validation of AVP
# values (other than Message-Authenticator). The table used to store request
# authenticators assumes you are only using this with a single RADIUS virtual
# server. If you use this library with many RADIUS virtual servers, move the
# "static::RA_table" declaration out of here and into irules specific to
# those servers with a unique value for each.
#
# The F5 supplied RADIUS library has good support for vendor AVPs. However, if
# you do have a need to use RADIUS_UTIL for this, here's an example that
# iterates through all the vendor specific AVPs:
#
# foreach {idx val} [array get AVP 26.*] {
#   binary scan $val Ia* vid bin_data
#   set output " Vendor($vid) "
#   call RADIUS_UTIL::avp_bin2array $bin_data VAVP
#   if {[array size VAVP] > 0} {
#     foreach vi [array names VAVP] {
#       append output "VAVP($vi): $VAVP($vi); "
#     }
#   } else {
#     append output "VAVP(raw): $bin_data; "
#   }
#   log local0. $output
# }
#
# The ability for me to assemble this library was very much thanks to the APM
# RADIUS server published by Stanislas Piron (whome in turn thanks John McInnes
# for his prior work and Kai Wilke for further assistance).
#
# Project home: https://github.com/CharlesDarwinUniversity/RADIUS_AUTH
#
################################################################################

when RULE_INIT {
  set static::RA_timeout 10
  set static::RA_table "RADIUS_UTIL"
  set static::RA_pp_err "RADIUS_UTIL::parse_packet ERROR"
  set static::RA_gp_err "RADIUS_UTIL::generate_packet ERROR"
  set static::RA_errm(0) "OK"
  set static::RA_errm(1) "Malformed RADIUS packet"
  set static::RA_errm(2) "Malformed RADIUS AVP data"
  set static::RA_errm(3) "Key is requred to validate RADIUS response packet"
  set static::RA_errm(4) "Request Authenticator not found, can not validate response packet"
  set static::RA_errm(5) "Failed to validate RADIUS response authenticator"
  set static::RA_errm(6) "Invalid Message-Authenticator or wrong key"
  set static::RA_errm(7) "Invalid or unsupported RADIUS auth code"
}

################################################################################
#
# RADIUS_UTIL::parse_packet payload ?key? ?out_avp? ?out_username? ?req_auth?
#
################################################################################
#
# Validates the payload and returns the RADIUS code when valid. Populates an
# output parameter with the AVP data as an array of multi-value type codes.
#
# Note: Doesn't return the packet ID becuase you can simply use RADIUS::id or
# binary scan.
#
# "out_username" is populated with User-Name. If this is a response code, and
# User-Name was not supplied it will lookup the stored Access-Request User-Name
# value (RFC2865 hints that the response User-Name could be preferred).
#
# Example usage:
#   set code [call RADIUS_UTIL::parse_packet [UDP::payload] $key avp]
#
################################################################################
proc parse_packet { payload {key ""} {out_avp ""} {out_username ""} { req_auth "" } { client_addr "" } } {
  if {$out_avp ne ""} { upvar $out_avp AVP }
  if {![array exists AVP]} { array set AVP {} }
  if {$out_username ne ""} { upvar $out_username USER_NAME }
  if {$client_addr eq ""} { set client_addr [IP::client_addr] }

  if { [catch {
    if { [binary scan $payload ccSa16 CODE IDENTIFIER PKT_LEN AUTHENTICATOR] != 4 || [set PKT_LEN [expr {$PKT_LEN & 0xFFFF}]] > [string length $payload] || $PKT_LEN > 4096} {
      error $static::RA_pp_err $static::RA_errm(1) 1
    } else {
      # Length field is valid (less than 4096 and less than payload length).
      # Octets outside the range of the Length field MUST be treated as padding and ignored on reception.
      set PAYLOAD [string range $payload 0 $PKT_LEN]
      set IDENTIFIER [expr {$IDENTIFIER & 0xFF}] ;# Unsigned (compatible with RADIUS:id)
    }

    # Support RADIUS auth codes only...
    switch -- $CODE {
      1 - 2 - 3 - 4 - 5 - 11 {

        if {$PKT_LEN > 20} {
          # Stores all attribute in AVP array with multiple value index of the format TYPE.SEQUENCE...
          call RADIUS_UTIL::avp_bin2array [string range $PAYLOAD 20 end] AVP msg_auth_offset
          if { [array size AVP] == 0 } {
            error $static::RA_pp_err $static::RA_errm(2) 2
          }
          if { $msg_auth_offset > -1 } {
            set record_offset [expr {$msg_auth_offset+20}]
            binary scan [string replace $PAYLOAD $record_offset [expr {$record_offset + 18}] [binary format ccH32 80 18 [string repeat 0 32]]] a* UNSIGNED_PAYLOAD
          }
        } elseif { [array exists AVP] } {
          array unset AVP
        }
        if {![array exists AVP]} { array set AVP {} } ;# Make sure we have an AVP array, even if it's empty

        set USER_NAME [expr {[info exists AVP(1.0)] ? $AVP(1.0) : ""}]

        # Process the authenticator...
        if { $CODE == 1 || $CODE == 4 } {  # Access-Request code...
          set req_auth $AUTHENTICATOR
          # Store Request Authenticator and User-Name for later...
          table set "$static::RA_table.$client_addr.$IDENTIFIER.RA" $AUTHENTICATOR $static::RA_timeout $static::RA_timeout
          table set "$static::RA_table.$client_addr.$IDENTIFIER.UN" $USER_NAME $static::RA_timeout $static::RA_timeout
        } else { # RADIUS response codes...
          if { $key eq "" } {
            error $static::RA_pp_err $static::RA_errm(3) 3
          }
          if { $req_auth eq "" } {
            set req_auth [table lookup "$static::RA_table.$client_addr.$IDENTIFIER.RA"]
            if { $req_auth eq ""} {
              error $static::RA_pp_err $static::RA_errm(4) 4
            }
          }
          set resp_auth [md5 [binary format ccSa16a[expr {$PKT_LEN-20}]a[string length $key] $CODE $IDENTIFIER \
                $PKT_LEN $req_auth [string range $PAYLOAD 20 end] $key ]]
          if { $resp_auth ne $AUTHENTICATOR } {
            error $static::RA_pp_err $static::RA_errm(5) 5
          }
          if { [info exists AVP(80.0)] } {
            # Patch Request Authenticator into UNSIGNED_PAYLOAD (see rfc2869, page 34)
            binary scan [string replace $UNSIGNED_PAYLOAD 4 19 $req_auth] a* UNSIGNED_PAYLOAD
          }
        }

        # If supplied, validate the Message-Authenticator...
        if { [info exists AVP(80.0)] && ($key eq "" || ![CRYPTO::verify -alg hmac-md5 -key $key -signature $AVP(80.0) $UNSIGNED_PAYLOAD]) } {
          error $static::RA_pp_err $static::RA_errm(6) 6
        }

        # Response doesn't contain User-Name, populate it from the Access-Request value...
        if { $CODE != 1 && $USER_NAME eq "" } {
          set USER_NAME [table lookup "$static::RA_table.$client_addr.$IDENTIFIER.UN"]
        }

      }
      default {
        error $static::RA_pp_err $static::RA_errm(7) 7
      }
    }
  }]}{ # Clean the out parameters on error
    array unset AVP *
    set USER_NAME ""
    error $static::RA_pp_err $::errorInfo $::errorCode
  }

  return $CODE
}

################################################################################
#
# RADIUS_UTIL::generate_packet code id key ?in_avp? ?force_msg_auth? ?req_auth?
#
################################################################################
#
# Returns a valid RADIUS packet payload.
#
# Example usage:
#   set payload [call RADIUS_UTIL::generate_packet $code $id $key avp 1]
#
################################################################################
proc generate_packet { code id key {in_avp ""} {force_msg_auth 0} { req_auth "" } { client_addr "" } } {
  if {$in_avp ne ""} { upvar $in_avp AVP } else { array set AVP {} }
  if {$client_addr eq ""} { set client_addr [IP::client_addr] }

  if { $req_auth eq "" } {
    set req_auth [table lookup "$static::RA_table.$client_addr.$id.RA"]
    if { $req_auth eq "" } {
      error $static::RA_gp_err $static::RA_errm(4) 4
    }
  }

  if { [info exists AVP(80.0)] } {
    # Remove the Message-Authenticator, setting the flag to reinsert it later
    set force_msg_auth 1
    unset AVP(80.0)
  }

  set bin_AVP [call RADIUS_UTIL::avp_array2bin AVP]
  set packet_length [expr { [string length $bin_AVP] + 20 }]

  if { $force_msg_auth==1 } {
    set UNSIGNED_AVP $bin_AVP[binary format ccH32 80 18 [string repeat 0 32]]
    incr packet_length 18
    append bin_AVP [binary format cc 80 18][CRYPTO::sign -alg hmac-md5 -key $key [binary format ccSa16a* \
          $code $id $packet_length $req_auth $UNSIGNED_AVP]]
  }

  if { $code==1 } { # Access-Request code...
    set authenticator $req_auth
  } else { # Assuming RADIUS response codes ( we could add $code validation here )
    set authenticator [md5 [binary format ccSa16a[expr {$packet_length-20}]a[string length $key] \
          $code $id $packet_length $req_auth $bin_AVP $key ]]
  }

  return [binary format ccSa16a* $code $id $packet_length $authenticator $bin_AVP]
}

################################################################################
#
# RADIUS_UTIL::avp_array2bin in_avp ?unsign?
#
################################################################################
#
# Returns the RADIUS binary string formatted representation of an AVP array.
#
# Unless "unsign" is set to 0, any Message-Authenticator value will be
# replaced with zeros as any value would be meaningless in this context.
#
# Example usage:
#   set binary_avp [call RADIUS_UTIL::avp_array2bin avp]
#
################################################################################
proc avp_array2bin { in_avp {unsign 1} } {
  upvar $in_avp AVP
  set binary ""

  foreach mv_idx [array names AVP] {
    set avp_type [expr {int($mv_idx)}]
    if { $avp_type != 80 || $unsign == 0 } {
      set avp_len [expr {[string length $AVP($mv_idx)]+2}]
      append binary [binary format cca* $avp_type $avp_len $AVP($mv_idx)]
    }
  }

  if { [info exists AVP(80.0)] && $unsign == 1 } {
    # Insert the unsigned Message-Authenticator
    append binary [binary format ccH32 80 18 [string repeat 0 32]]
  }

  return $binary
}

################################################################################
#
# RADIUS_UTIL::avp_bin2array binary out_avp ?out_msg_auth_offset?
#
################################################################################
#
# Interprets "binary" as RADIUS AVP data and populates the array specified by
# the output parameter "out_avp".
#
# "out_msg_auth_offset" is used to get the offset of the Message-Authenticator
# in the binary data incase you want to know if it exists or unsign it. This
# feature is really only here to make packet parsing a little more efficient.
#
# Example usage:
#   set binary_avp [call RADIUS_UTIL::avp_array2bin avp]
#
################################################################################
proc avp_bin2array { binary out_avp { out_msg_auth_offset "" } } {
  upvar $out_avp AVP
  if {[array exists AVP]} { array unset AVP }
  if { $out_msg_auth_offset ne "" } { upvar $out_msg_auth_offset msg_auth_offset }
  set msg_auth_offset -1
  set bin_len [string length $binary]
  array set multi_value_index {}

  for {set avp_offset 0} {$avp_offset < $bin_len } {incr avp_offset $avp_len} {
    if {([binary scan $binary @${avp_offset}cc avp_type avp_len] != 2) || ([set avp_len [expr {$avp_len & 0xFF}]] < 3) || ($avp_offset+$avp_len > $bin_len) } {
      # This is not valid AVP data, trash the array and bail...
      array unset AVP
      break
    }
    set avp_type [expr {$avp_type & 0xFF}]

    if { $avp_type==80 } { set msg_auth_offset $avp_offset }

    if {![info exists multi_value_index($avp_type)]} { set multi_value_index($avp_type) -1 }
    set mv_idx "$avp_type.[incr multi_value_index($avp_type)]"

    binary scan $binary @${avp_offset}x2a[expr {$avp_len -2}] AVP($mv_idx)
  }
  if { not([array exists AVP]) }{ array set AVP {} }
}

################################################################################
#
# RADIUS_UTIL::pw_decrypt key req_auth encoded_password
#
################################################################################
#
# Decryption algorithm for User-Password attribute, contributed by Stanislas
# Piron.
#
# Returns the decrypted password.
#
# Example usage:
#   binary scan [UDP::payload] @4a16 req_auth
#   set pw [call RADIUS_UTIL::pw_decrypt $key $req_auth $AVP(2)]
#
################################################################################
proc pw_decrypt { key req_auth encoded_password } {
  binary scan [md5 $key$req_auth] WW bx_64bits_1 bx_64bits_2
  binary scan $encoded_password W* encoded_password_w_list
  set password_list [list]
  foreach {cx_64bits_1 cx_64bits_2} $encoded_password_w_list {
    lappend password_list [expr { $cx_64bits_1 ^ $bx_64bits_1 }] [expr { $cx_64bits_2 ^ $bx_64bits_2 }]
    binary scan [md5 $key[binary format WW $cx_64bits_1 $cx_64bits_2]] WW bx_64bits_1 bx_64bits_2
  }
  binary scan [binary format W* $password_list] A* password
  return $password
}

################################################################################
#
# RADIUS_UTIL::pw_encrypt key req_auth password
#
################################################################################
#
# Encryption algorithm for User-Password attribute, contributed by Stanislas
# Piron.
#
# Returns the encrypted password.
#
# Example usage:
#   binary scan [UDP::payload] @4a16 req_auth
#   set AVP(2) [call RADIUS_UTIL::pw_encrypt $key $req_auth "my password"]
#
################################################################################
proc pw_encrypt { key req_auth password } {
  binary scan [md5 $key$req_auth] WW bx_64bits_1 bx_64bits_2
  binary scan [binary format a[expr {[string length $password] + 16 - [string length $password]%16}] $password ] W* password_w_list
  set encoded_password_list [list]
  foreach {px_64bits_1 px_64bits_2} $password_w_list {
    lappend encoded_password_list [expr { $px_64bits_1 ^ $bx_64bits_1 }] [expr { $px_64bits_2 ^ $bx_64bits_2 }]
    binary scan [md5 $key[binary format W2 [lrange $encoded_password_list end-1 end]]] WW bx_64bits_1 bx_64bits_2
  }
  binary scan [binary format W* $encoded_password_list] A* encoded_password
  return $encoded_password
}

proc forget_request { identifier } {
  table delete "$static::RA_table.[IP::client_addr].${identifier}.RA"
  table delete "$static::RA_table.[IP::client_addr].${identifier}.UN"
}

################################################################################
#
# RADIUS_UTIL::ipv4_to_octets ip
#
################################################################################
#
# Useful for manipulating IPv4 attributes such as NAS-IP-Address
#
# Returns the 4 byte representation of an IPv4 string
#
################################################################################
proc ipv4_to_octets {ip} {
  set octets [split $ip .]
  foreach oct $octets {
    if {$oct < 0 || $oct > 255} {
      set octets [list 0 0 0 0]
      break
    }
  }
  if { [llength $octets] != 4 } { set octets [list 0 0 0 0] }
  return [binary format c4 $octets]
}
