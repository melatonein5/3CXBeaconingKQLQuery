# 3CXBeaconingKQLQuery
KQL to detect beaconing to IOCs from the 3CX compromise 

## Sentinel DNS query (using ASIM Normalization)

```
let IOC = dynamic(["akamaicontainer.com","akamaitechcloudservices.com","azuredeploystore.com","azureonlinecloud.com","azureonlinestorage.com","dunamistrd.com","glcloudservice.com","journalide.org","msedgepackageinfo.com","msstorageazure.com","msstorageboxes.com","officeaddons.com","officestoragebox.com","pbxcloudeservices.com","pbxphonenetwork.com","pbxsources.com","qwepoi123098.com","sbmsa.wiki","sourceslabs.com", "visualstudiofactory.com","zacharryblogs.com"]);
_Im_Dns
| where DnsQuery in~ (IOC)
```

## MDE Advanced Hunting

```
let IOC = dynamic(["akamaicontainer.com","akamaitechcloudservices.com","azuredeploystore.com","azureonlinecloud.com","azureonlinestorage.com","dunamistrd.com","glcloudservice.com","journalide.org","msedgepackageinfo.com","msstorageazure.com","msstorageboxes.com","officeaddons.com","officestoragebox.com","pbxcloudeservices.com","pbxphonenetwork.com","pbxsources.com","qwepoi123098.com","sbmsa.wiki","sourceslabs.com", "visualstudiofactory.com","zacharryblogs.com"]);
DeviceNetworkEvents
| where RemoteUrl in~ (IOC)
```
