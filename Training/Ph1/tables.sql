/****** LoadScript Example for Collected IR Files, Script Date: 3/16/2016 2:50:32 PM ******/

USE [training]
GO

drop table netstat
go
drop table autoruns
go
drop table processes
go
drop table startups
go
drop table tasks
go
drop table dir
go
drop table software
go


/****** Object:  Table [dbo].[netstat] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[netstat]
(
	[hostname] [text] NULL,
	[protocol] [varchar](8) NULL,
	[localaddr] [varchar](128) NULL,
	[remoteaddr] [varchar](128) NULL,
	[status] [varchar](32) NULL,
	[pid] [varchar](16) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert netstat
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\netstat.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go


/****** Object:  Table [dbo].[startups] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[startups]
(
	[hostname] [text] NULL,
	[fullpath] [varchar](256) NULL,
	[md5] [varchar](256) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert startups
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\startups.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go



/****** Object:  Table [dbo].[autoruns] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[autoruns]
(
	[hostname] [text] NULL,
	[keyname] [varchar](256) NULL,
	[keyvalue] [varchar](256) NULL,
	[fullpath] [varchar](256) NULL,
	[md5] [varchar](256) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert autoruns
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\autoruns.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go



/****** Object:  Table [dbo].[processes] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[processes]
(
	[hostname] [text] NULL,
	[processname] [varchar](max) NULL,
	[fullpath] [varchar](256) NULL,
	[md5] [varchar](256) NULL,
	[pid] [varchar](max) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert processes
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\processes.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go


/****** Object:  Table [dbo].[tasks] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[tasks]
(
	[hostname] [text] NULL,
	[taskname] [varchar](256) NULL,
	[fullpath] [varchar](256) NULL,
	[md5] [varchar](256) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert tasks
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\scheduledtasks.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go



/****** Object:  Table [dbo].[dir] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[dir]
(
	[hostname] [text] NULL,
	[fullpath] [varchar](256) NULL,
	[filename] [varchar](256) NULL,
	[filetype] [varchar](256) NULL,
	[filesize] [varchar](64) NULL,
	[datecreated] [datetime] NULL,
	[dateaccessed] [datetime] NULL,
	[datemodified] [datetime] NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert dir
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\listfiles.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go




/****** Object:  Table [dbo].[software] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[software]
(
	[hostname] [text] NULL,
	[filename] [varchar](256) NULL,
	[dateinstalled] [datetime] NULL,
	[vendor] [varchar](256) NULL,
	[vendorname] [varchar](256) NULL,
	[productname] [varchar](256) NULL,
	[productversion] [varchar](256) NULL,
	[installpath] [varchar](256) NULL,
	[productpackage] [varchar](256) NULL,
	[packageversion] [varchar](256) NULL
) ON [PRIMARY]


GO

SET ANSI_PADDING OFF
GO

bulk insert software
from 'C:\Users\sshook\Desktop\Training\Training\Ph1\collected\software.csv'
with (fieldterminator = ',', rowterminator = '0x0a', MAXERRORS=999999)
go