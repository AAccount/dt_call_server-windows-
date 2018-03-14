CREATE TABLE [dbo].[Users] (
    [Username] VARCHAR (50) NOT NULL,
    [Keydump]  TEXT         NOT NULL,
    [Enabled]  BIT          DEFAULT ((1)) NOT NULL,
    PRIMARY KEY CLUSTERED ([Username] ASC)
);

