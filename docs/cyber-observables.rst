Mappings from STIX 2.x to CybOX 2.x
========================================

The following table associates the CybOX 2.x object types with their STIX 2.x cyber observable types.
For each CybOX object the table also indicates if the slider is able to convert the cyber observable object to CybOX 2.x.

CybOX object types not listed have no corresponding STIX 2.x cyber observable type, and therefore are not
converted by the slider.

============================================= ============================================= ==============================================
**STIX 2.x Cyber Observable Type**            **CybOX 2.x Type**                            **Converted in version 2.0.0 of the Slider**
============================================= ============================================= ==============================================
``artifact``                                  Artifact                                      yes
``autonomous-system``                         AutonomousSystem                              yes
``directory``                                 File                                          yes
``domain-name``                               DomainName                                    yes
``email-addr``                                Address                                       yes
``email-message``                             EmailMessage                                  yes
``file``                                      File                                          yes
``file:archive-ext``                          ArchiveFile                                   yes
``file:raster-image-ext``                     ImageFile                                     yes
``file:ntfs-ext``                             WinFile                                       yes
``file:pdf-ext``                              PDFFile                                       yes
``file:window-pebinary-ext``                  WinExecutableFile                             yes
``ipv4-addr``                                 Address                                       yes
``ipv6-addr``                                 Address                                       yes
``mac-addr``                                  Address                                       yes
``mutex``                                     Mutex                                         yes
``network-traffic``                           NetworkConnection                             yes
``network-traffic:http-request-ext``          NetworkConnection and HTTPClientRequest       yes
``network-traffic:icmp-ext``                  NetworkConnection and ICMPv4Packet            yes
``network-traffic:socket-ext``                NetworkConnection and NetworkSocket           yes
``network-traffic:tcp-ext``                   *none*                                        no
``process``                                   Process                                       yes
``process:windows-process-ext``               WinProcess                                    yes
``process:windows-service-ext``               WinService                                    yes
``software``                                  Product                                       yes
``url``                                       URI                                           yes
``user-account``                              UserAccount, WinUser, UnixUserAccount         yes
``user-account:unix-account-ext``             UnixUserAccount                               yes
``window-registry-key``                       WinRegistryKey                                yes
``x509-certificate``                          X509Certificate                               yes
``x509-certificate:x509-v3-extensions-type``  X509Certificate and X509V3Extensions          yes
============================================= ============================================= ==============================================
