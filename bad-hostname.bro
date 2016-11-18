@load base/frameworks/notice
@load policy/protocols/smb

export {
    redef enum Notice::Type += {
        HostMatch
    };

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{

# strip out first 5 characters of workstation value to be compared to company convention
local strcheck = sub_bytes(request$workstation, 1, 5);


# value of the comparison of the two strings
local comp_str = strcmp(strcheck, " Enter a string that is common across most or all of the hostnames on your network");

        # If the comparison of the strings stored in comp_str are not the same, generate a notice.
        if (comp_str != 0 )
        {
        NOTICE([$note=HostMatch, $msg=fmt("Potential Lateral Movement Activity - Invalid Hostname using Domain Credentials"), $sub=fmt("%s,%s","Suspicious Hostname:", request$workstation), $conn=c]);
        }
}
}
