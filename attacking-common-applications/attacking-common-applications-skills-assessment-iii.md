# Attacking Common Applications - Skills Assessment III

During our penetration test our team found a Windows host running on the network and the corresponding credentials for the Administrator. It is required that we connect to the host and find the `hardcoded password` for the MSSQL service.

**Questions**

What is the hardcoded password for the database connection in the MultimasterAPI.dll file?

```bash
#in dnSpy
MultimasterAPI.Controllers → ColleagueController
#string connString = "server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```
