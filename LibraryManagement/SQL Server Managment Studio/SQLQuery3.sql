USE [LibraryManagmentSystem]
GO

/****** Object:  Table [dbo].[books]    Script Date: 2/12/2026 4:34:04 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[books](
	[id] [bigint] IDENTITY(1,1) NOT NULL,
	[genre] [varchar](255) NULL,
	[isbn] [varchar](255) NOT NULL,
	[title] [varchar](255) NOT NULL,
	[author_id] [bigint] NOT NULL,
	[available] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
 CONSTRAINT [UKkibbepcitr0a3cpk3rfr7nihn] UNIQUE NONCLUSTERED 
(
	[isbn] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[books]  WITH CHECK ADD  CONSTRAINT [FKfjixh2vym2cvfj3ufxj91jem7] FOREIGN KEY([author_id])
REFERENCES [dbo].[authors] ([id])
GO

ALTER TABLE [dbo].[books] CHECK CONSTRAINT [FKfjixh2vym2cvfj3ufxj91jem7]
GO


