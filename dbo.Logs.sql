CREATE TABLE [dbo].[Logs] (
    [Id]           INT          IDENTITY (1, 1) NOT NULL,
    [LogTimestamp] ROWVERSION   NOT NULL,
    [Tag]          VARCHAR (20) NOT NULL,
    [Message]      TEXT         NOT NULL,
    [User]         VARCHAR (50) NOT NULL,
    [Type]         VARCHAR (10) NOT NULL,
    [Ip]           VARCHAR (12) NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);

