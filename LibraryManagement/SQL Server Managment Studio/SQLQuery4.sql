USE [LibraryManagmentSystem]
GO

/****** Object:  Table [dbo].[lendings]    Script Date: 2/12/2026 4:34:09 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[lendings](
	[id] [bigint] IDENTITY(1,1) NOT NULL,
	[borrow_date] [date] NULL,
	[borrower_name] [varchar](255) NULL,
	[return_date] [date] NULL,
	[returned] [bit] NOT NULL,
	[book_id] [bigint] NOT NULL,
	[user_id] [bigint] NULL,
	[actual_return_date] [date] NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[lendings]  WITH CHECK ADD  CONSTRAINT [FKisb7wu7w4af6fpilljihmgonx] FOREIGN KEY([book_id])
REFERENCES [dbo].[books] ([id])
GO

ALTER TABLE [dbo].[lendings] CHECK CONSTRAINT [FKisb7wu7w4af6fpilljihmgonx]
GO

ALTER TABLE [dbo].[lendings]  WITH CHECK ADD  CONSTRAINT [FKqssf0a8uqguu051xfg8l9fp6p] FOREIGN KEY([user_id])
REFERENCES [dbo].[users] ([id])
GO

ALTER TABLE [dbo].[lendings] CHECK CONSTRAINT [FKqssf0a8uqguu051xfg8l9fp6p]
GO


