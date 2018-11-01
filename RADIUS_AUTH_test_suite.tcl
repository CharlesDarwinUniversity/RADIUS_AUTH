# RADIUS_AUTH_test_suite
#
# Used to verify the integrity of RADIUS_AUTH if it's not working or any changes are made
# Attach this irule to an HTTP virtual server along with RADIUS_AUTH to run tests and view results via web browser

proc bin2hex { binary {sep " "} } {
	# Returns a hex string in 4 byte chunks...
	set LENGTH [string length $binary]
	set dump_string ""

	for {set line_offset 0} {$line_offset < $LENGTH } {incr line_offset 4} {
		binary scan [string range $binary $line_offset [expr {$line_offset+3}]] H* hex_line
		append dump_string "$hex_line$sep"
	}
	return $dump_string
}

proc html_encode { str } {
	set encoded ""
	foreach char [split $str ""] {
		switch -- "$char" {
			"<" { append encoded "&lt;" }
			">" { append encoded "&gt;" }
			"'" { append encoded "&apos;" }
			\" { append encoded "&quot;" }
			"&" { append encoded "&amp;" }
			default { append encoded $char }
		}
	}
	return $encoded
}

proc avp_debug { in_avp {indent ""} } {
	upvar $in_avp AVP

	set output ""

	foreach mv_idx [array names AVP] {
		set attrLength [expr {[string length $AVP($mv_idx)]+2}]
		#set attrID [expr {int($attrID)}]
		set data $AVP($mv_idx)
		append output "${indent}AVP($mv_idx):\n${indent}  Raw($attrLength): [call html_encode $data]\n${indent}  Hex: [call bin2hex $data]\n"
	}
	return $output
}

proc random_hex_string { length } {
	# Note the additional "f" is for the very unlikely event that rand() returns 1...
	set symbols "0123456789abcdeff"
	set str ""
	for {set i 0} {$i < $length} {incr i} {
		set pos [expr {int(rand()*16)}]
		append str [string range $symbols $pos $pos]
	}
	return $str
}

proc random_avp { type max_length } {
	set hex_len [expr {2+int(rand()*$max_length)*2}] ;# Random positive even integer
	set data [binary format H* [call random_hex_string $hex_len]]
	set data [string range $data 0 [expr {$max_length-3}]] ;# Make sure the string is within maximum
	return [binary format cca* $type [expr {[string length $data] + 2}] $data]
}

proc random_radius_payload { code id key {min_length 20} {max_avp_length 50} {msg_auth 0} {req_auth ""} } {
	set payload [binary format cccc $code $id 0 0]

	if { $req_auth eq "" } { set req_auth [binary format H32 [call random_hex_string 32]] }

	if { $code==1 } {
		set authenticator $req_auth
	} else {
		set authenticator [binary format H32 [string repeat 0 32]]
	}

	append payload $authenticator

	# Generate some AVP data...
	while {[string length $payload] < $min_length} {
		set avp_type [expr {int(rand()*255)}]

		if { $avp_type == 26 } {
			# RFC2865 allows for random junk or structured data...
			set vendor_id [expr {int(rand()*4294967295)}]
			set data [binary format i $vendor_id]
			if { [expr {rand()}] > 0.5 } {
				# Add random junk...
				set hex_len [expr {2+int(rand()*$max_avp_length)*2}]
				append data [binary format H* [call random_hex_string $hex_len]]
			} else {
				# Add structured junk...
				set vsa_type [expr {int(rand()*255)}]
				append data [call random_avp $vsa_type [expr {$max_avp_length-[string length $data] - 2}]]
				while { [string length $data] < [expr {$max_avp_length-10}] && [expr {rand()}] > 0.5 } {
					# If there's still room, randomly add another vsa...
					set vsa_type [expr {int(rand()*255)}]
					append data [call random_avp $vsa_type [expr {$max_avp_length-[string length $data] - 2}]]
				}
			}
			append payload [binary format cca* $avp_type [expr {[string length $data] + 2}] $data]
		} elseif { $avp_type != 80 } {
			append payload [call random_avp $avp_type $max_avp_length]
		}
	}

	set pl_length [string length $payload]

	if { $msg_auth==1 } {
		# Append Message-Authenticator...
		incr pl_length 18
		set unsigned_payload [string replace $payload 4 19 $req_auth][binary format ccH32 80 18 [string repeat 0 32]]
		set unsigned_payload [string replace $unsigned_payload 2 3 [binary format S $pl_length]]
		append payload [binary format cc 80 18][CRYPTO::sign -alg hmac-md5 -key $key [binary format a* $unsigned_payload]]
	}

	set payload [string replace $payload 2 3 [binary format S $pl_length]]

	if { $code > 1 } {
		set authenticator [md5 [binary format ccSa16a[expr {$pl_length-20}]a[string length $key] $code $id \
							$pl_length $req_auth [string range $payload 20 end] $key ]]
		set payload [string replace $payload 4 19 $authenticator]
	}

	return $payload
}

proc fail_dump {code in_avp error payload} {
	upvar $in_avp AVP
	if {![array exists AVP]} { array set AVP {} }
	set avp_indent "    "
	return "Test suite failed, dumping variable state after last test...
	ERROR: $static::RA_errm($error)
	PAYLOAD: [call bin2hex $payload]
	CODE: $code
	AVP ARRAY:
[call avp_debug AVP $avp_indent]"
}

proc run_tests {} {

	set key "BogusMcTestkey"
	set test_log "Test Suite Starting\n"
	set code 0
	array set AVP {}

	append test_log "Test for failure to parse 100 bytes of random junk... "
	set payload [binary format H* [call random_hex_string 200]]
	if { ![catch { set code [call RADIUS_AUTH::parse_packet $payload $key AVP] } ]} {
		append test_log "WARNING - successfully parsed random junk\n"
	} elseif { $::errorCode == 0 } {
		append test_log "FAILED - failed to set an error message\n"
	} elseif { not([array exists AVP])  } {
		append test_log "FAILED - out_avp did not return an array object\n"
	} elseif { [array size AVP] > 0 } {
		append test_log "FAILED - out_avp contains values when it should be empty\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test for failure to parse a random Access-Request packet with Message-Authenticator and wrong key... "
	set req_auth [binary format H32 [call random_hex_string 32]]
	set id [expr {int(rand()*255)}]
	set payload [call random_radius_payload 1 $id $key 21 50 1 $req_auth]

	if { ![catch { set code [call RADIUS_AUTH::parse_packet $payload "wrong key" AVP] } ] && $code == 1 } {
		append test_log "FAILED - request parsed ok\n"
	} elseif { $::errorCode == 0 } {
		append test_log "FAILED - failed to set an error message\n"
	} elseif { not([array exists AVP])  } {
		append test_log "FAILED - out_avp did not return an array object\n"
	} elseif { [array size AVP] > 0 } {
		append test_log "FAILED - out_avp contains values when it should be empty\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test parsing a random Access-Request packet with no AVP data... "
	set req_auth [binary format H32 [call random_hex_string 32]]
	set id [expr {int(rand()*255)}]
	set payload [call random_radius_payload 1 $id $key 1 0 0 $req_auth]
	if { ![catch { set code [call RADIUS_AUTH::parse_packet $payload $key AVP] } ] && $code == 1 } {
		if { not([array exists AVP])  } {
			append test_log "FAILED - out_avp did not return an array object\n"
		} elseif { [array size AVP] != 0 } {
			append test_log "FAILED - out_avp contains items when it should be empty\n"
		} else {
			append test_log "PASSED\n"
		}
	} else {
		append test_log "FAILED - $::errorInfo\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test parsing a random Access-Request packet with random junk instead of AVP data... "
	set req_auth [binary format H32 [call random_hex_string 32]]
	set id [expr {int(rand()*255)}]
	set payload [call random_radius_payload 1 $id $key 120 80 0 $req_auth]
	set hex_len [expr {2*([string length $payload]-20)}]
	set avp_junk [binary format H$hex_len [call random_hex_string $hex_len]]
	set payload [string range $payload 0 19]$avp_junk
	catch { set code 0; set code [call RADIUS_AUTH::parse_packet $payload $key AVP] }
	if { not([array exists AVP])  } {
		append test_log "FAILED - out_avp did not return an array object\n"
	} elseif { $code > 0 && [array size AVP] > 0 } {
		append test_log "WARNING - successfully parsed random junk in AVP data\n"
	} elseif { $code > 0 } {
		append test_log "FAILED - parsed packet with random junk in AVP data\n"
	} elseif { $::errorCode == 0 } {
		append test_log "FAILED - failed to set an error message\n"
	} elseif { [array size AVP] > 0 } {
		append test_log "FAILED - out_avp contains values when it should be empty\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test parsing a random Access-Request packet with Message-Authenticator... "
	set req_auth [binary format H32 [call random_hex_string 32]]
	set id [expr {int(rand()*255)}]
	set payload [call random_radius_payload 1 $id $key 21 50 1 $req_auth]
	if { ![catch { set code [call RADIUS_AUTH::parse_packet $payload $key AVP] } ] && $code == 1 } {
		if { not([array exists AVP])  } {
			append test_log "FAILED - out_avp did not return an array object\n"
		} elseif { [array size AVP] < 1 } {
			append test_log "FAILED - out_avp is empty although AVP data existed\n"
		} elseif { not([info exists AVP(80.0)]) } {
			append test_log "FAILED - Message-Authenticator not found in out_avp\n"
		} else {
			append test_log "PASSED\n"
		}
	} else {
		append test_log "FAILED - $::errorInfo\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test generating a corresponding Access-Reject packet with AVP data... "
	set error 1
	array unset AVP *
	set AVP(18.0) "This is a Reply-Message"
	if { [catch {set payload [call RADIUS_AUTH::generate_packet 3 $id $key AVP 1 $req_auth]}] } {
		if { $::errorCode == 0 } {
			append test_log "FAILED - also, out_error was not set!\n"
		} else {
			append test_log "FAILED - $::errorInfo\n"
		}
	} elseif { [string length $payload] <= 20 } {
		append test_log "FAILED - payload doen't contain AVP data\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test the generated payload for Reply-Message and Message-Authenticator... "
	set binAVP [string range $payload 20 end]
	array unset AVP
	call RADIUS_AUTH::avp_bin2array $binAVP AVP msg_auth_offset
	if { not([array exists AVP])  } {
		append test_log "FAILED - out_avp did not return an array object\n"
	} elseif { [array size AVP] != 2 } {
		append test_log "FAILED - out_avp contains wrong number of values\n"
	} elseif { ![info exists AVP(18.0)] || $AVP(18.0) ne "This is a Reply-Message" } {
		append test_log "FAILED - Reply-Message value in out_avp has changed to an unexpected value\n"
	} elseif { ![info exists AVP(80.0)] } {
		append test_log "FAILED - Message-Authenticator is missing from out_avp\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test generating a corresponding Access-Reject packet without AVP data... "
	set error 1
	if { [catch {set payload [call RADIUS_AUTH::generate_packet 3 $id $key "" 0 $req_auth]}] } {
			append test_log "FAILED - $::errorInfo\n"
	} elseif { [string length $payload] != 20 } {
		append test_log "FAILED - payload appears to contain AVP data\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test generating an Access-Reject packet without a Request Authenticator fails... "
	set error 0
	set another_id $id
	while { $another_id == $id } { set another_id [expr {int(rand()*255)}] }
	table delete "$static::RA_table.[IP::client_addr].$another_id"
	if { [catch {set payload [call RADIUS_AUTH::generate_packet 3 $another_id $key "" 0 ""]}] } {
		append test_log "PASSED\n"
	} else {
		append test_log "FAILED - payload generated\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Parse a generated Access-Reject packet... "
	array unset AVP *
	set AVP(18.0) "This is a Reply-Message"
	set payload [call RADIUS_AUTH::generate_packet 3 $id $key AVP 1 $req_auth]
	binary scan [string range $payload 1 1] c payload_id
	set payload_id [expr {$payload_id & 0xFF}]
	if { [catch {set code [call RADIUS_AUTH::parse_packet $payload $key AVP "" $req_auth]}] } {
		append test_log "FAILED - $::errorInfo\n"
	} elseif { $code != 3 } {
		append test_log "FAILED - returned wrong RADIUS code: $code\n"
	} elseif { $id != $payload_id } {
		append test_log "FAILED - wrong id\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }


	append test_log "Fail to parse a generated Access-Reject packet with wrong Request Authenticator... "
	array unset AVP *
	set AVP(18.0) "This is a Reply-Message"
	set payload [call RADIUS_AUTH::generate_packet 3 $id $key AVP 1 $req_auth]
	binary scan [string range $payload 1 1] c payload_id
	set payload_id [expr {$payload_id & 0xFF}]
	if { ![catch {set code [call RADIUS_AUTH::parse_packet $payload $key AVP "" [binary format H32 [call random_hex_string 32]]] }]} {
		append test_log "FAILED - Parsed packet\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }


	append test_log "Fail to parse a generated Access-Reject packet with wrong Key... "
	array unset AVP *
	set AVP(18.0) "This is a Reply-Message"
	set payload [call RADIUS_AUTH::generate_packet 3 $id $key AVP 1 $req_auth]
	binary scan [string range $payload 1 1] c payload_id
	set payload_id [expr {$payload_id & 0xFF}]
	if { ![catch {set code [call RADIUS_AUTH::parse_packet $payload "WrongKey" AVP "" $req_auth] }]} {
		append test_log "FAILED - Incorrectly parsed packet\n"
	} else {
		append test_log "PASSED\n"
	}

	if {[string match *FAILED* $test_log]} { append test_log [call fail_dump $code AVP $::errorCode $payload]; return $test_log }

	append test_log "Test Suite Complete\n"

	return $test_log
}

when HTTP_REQUEST priority 600 {

	set desc "This will test some critical core functionality of RADIUS_AUTH"

	set log [call run_tests]

	HTTP::respond 403 content "
<html>
<head>
				<title>RADIUS_AUTH_test_suite</title>
</head>
<body><h3>$desc</h3>
<pre>
$log
</pre>
</body></html>
" Content-Type text/html Connection Close
}