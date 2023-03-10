import discord
from dotenv import load_dotenv
import os
import random
from asyncio import events
from nturl2path import url2pathname
import re
from urllib import response
import json
import requests
import datetime
import shutil
import time
from discord.ext import commands
import discord_downloader as dd
import argparse
from discord_downloader.config import cfg
from discord_downloader.parser import base_parser
from discord_downloader.utils import (
    none_or_int,
    none_or_str,
    none_or_date,
    none_or_list,
)

ruta = "C:/Users/cf2021166/Documents/visual studio code/DDiscord/DDiscord"

base_parser = argparse.ArgumentParser(
    description="Download files and attachments from Discord!"
)
# GRAB THE API TOKEN FROM THE .ENV FILE.
DISCORD_TOKEN = os.getenv("wl6Ay27pSz7H5pYXtUg5q0dN63vDsXkz")
TOKEN = os.getenv("MTAzMTU2MTM2MjAyOTE1MDM2OA.GsbkhI.LH7IIW_Hw8TVIaedYiAZnn3u1bcQUquhIai6eg")
token = os.getenv("MTAzMTU2MTM2MjAyOTE1MDM2OA.GsbkhI.LH7IIW_Hw8TVIaedYiAZnn3u1bcQUquhIai6eg")


def get_quote():
  response = requests.get("https://zenquotes.io/api/random")
  json_data = json.loads(response.text)
  quote = json_data[0]['q'] + " -" + json_data[0]['a']
  return(quote)

# IMPORT DISCORD.PY. ALLOWS ACCESS TO DISCORD'S API.
import discord

# IMPORT THE OS MODULE.
import os

# IMPORT LOAD_DOTENV FUNCTION FROM DOTENV MODULE.
from dotenv import load_dotenv

# LOADS THE .ENV FILE THAT RESIDES ON THE SAME LEVEL AS THE SCRIPT.
load_dotenv()



#2bf8d4da3e914127295af5ffbd5e0b4273cf5e5a782c3103b7b691b74f737d57


client = "wl6Ay27pSz7H5pYXtUg5q0dN63vDsXkz",
token = "MTAzMTU2MTM2MjAyOTE1MDM2OA.GsbkhI.LH7IIW_Hw8TVIaedYiAZnn3u1bcQUquhIai6eg",
filetypes=none_or_str(cfg.get("args", "filetypes")),
output_dir=str(cfg.get("args", "output_dir")),
channels=none_or_list(cfg.get("args", "channels")),
server=none_or_str(cfg.get("args", "server")),
dry_run=cfg.getboolean("args", "dry_run"),
num_messages=none_or_int(cfg.get("args", "num_messages")),
verbose=cfg.getboolean("args", "verbose"),
prepend_user=cfg.getboolean("args", "prepend_user"),
after=none_or_date(cfg.get("args", "after")),
before=none_or_date(cfg.get("args", "before")),
zipped=cfg.getboolean("args", "zipped"),
include_str=none_or_str(cfg.get("args", "include_str")),
exclude_str=none_or_str(cfg.get("args", "exclude_str")),

def main(
    client = "wl6Ay27pSz7H5pYXtUg5q0dN63vDsXkz",
    token = "MTAzMTU2MTM2MjAyOTE1MDM2OA.GsbkhI.LH7IIW_Hw8TVIaedYiAZnn3u1bcQUquhIai6eg",
    filetypes=none_or_str(cfg.get("args", "filetypes")),
    output_dir=str(cfg.get("args", "output_dir")),
    channels=none_or_list(cfg.get("args", "channels")),
    server=none_or_str(cfg.get("args", "server")),
    dry_run=cfg.getboolean("args", "dry_run"),
    num_messages=none_or_int(cfg.get("args", "num_messages")),
    verbose=cfg.getboolean("args", "verbose"),
    prepend_user=cfg.getboolean("args", "prepend_user"),
    after=none_or_date(cfg.get("args", "after")),
    before=none_or_date(cfg.get("args", "before")),
    zipped=cfg.getboolean("args", "zipped"),
    include_str=none_or_str(cfg.get("args", "include_str")),
    exclude_str=none_or_str(cfg.get("args", "exclude_str")),
):print("")



# GETS THE CLIENT OBJECT FROM DISCORD.PY. CLIENT IS SYNONYMOUS WITH BOT.
#bot = discord.Client(intents=discord.Intents.all() , command_prefix= "!" , description='The Best Bot For the Best User!',help_command=None)
bot = commands.Bot(intents=discord.Intents.all() , command_prefix= "!" , description='The Best Bot For the Best User!')



# EVENT LISTENER FOR WHEN THE BOT HAS SWITCHED FROM OFFLINE TO ONLINE.
@bot.event
async def on_ready(
		server=server,
        channels=channels,
        num_messages=num_messages,
        filetypes=filetypes,
        verbose=verbose,
        output_dir=output_dir,
        prepend_user=prepend_user,
        dry_run=dry_run,
        after=after,
        before=before,
        include_str=include_str,
        exclude_str=exclude_str,
):
	# CREATES A COUNTER TO KEEP TRACK OF HOW MANY GUILDS / SERVERS THE BOT IS CONNECTED TO.
	guild_count = 0
	print(f'{bot.user} has connected to Discord!')
	await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="!help"))
	# LOOPS THROUGH ALL THE GUILD / SERVERS THAT THE BOT IS ASSOCIATED WITH.
	for guild in bot.guilds:
		# PRINT THE SERVER'S ID AND NAME.
		print(f"- {guild.id} (name: {guild.name})")

		# INCREMENTS THE GUILD COUNTER.
		guild_count = guild_count + 1

	# PRINTS HOW MANY GUILDS / SERVERS THE BOT IS IN.
	print("SampleDiscordBot is in " + str(guild_count) + " guilds.")      

	

# EVENT LISTENER FOR WHEN A NEW MESSAGE IS SENT TO A CHANNEL.



@bot.event
async def on_message(message,
		server=server,
        channels=channels,
        num_messages=num_messages,
        filetypes=filetypes,
        verbose=verbose,
        output_dir=output_dir,
        prepend_user=prepend_user,
        dry_run=dry_run,
        after=after,
        before=before,
        include_str=include_str,
        exclude_str=exclude_str,
		):
		# CHECKS IF THE MESSAGE THAT WAS SENT IS EQUAL TO "HELLO".
		if message.content.startswith("!help"):
			# SENDS BACK A MESSAGE TO THE CHANNEL.
			await message.channel.send("buscat la vida bro")
		elif message.content.startswith == "!ping" or message.content.startswith == "!beep":
			if message.content == "!beep":
				await message.channel.send("boop")
			else:
				await message.channel.send("pong")
		elif message.content.startswith("!inspire"):
			quote = get_quote()
			await message.channel.send(quote)
		elif message.content.startswith("!scan") or  message.content.startswith("!s"):
			await message.channel.send("Scanning on....")
			download_dir = ruta + datetime.datetime.now().strftime("%Y%m%d")
			output_dir = os.path.join(download_dir)
			os.makedirs(output_dir, exist_ok=True)
			#await message.channel.send(download_dir)
			#await message.channel.send(output_dir)
			
			if server is None:
				server = bot.guilds[0].name  # Default to first server
			server = bot.guilds[0].name
			if (after is not None and before is not None) or (
				num_messages is None or num_messages <= 0
			):
				num_messages = None  # Grab all files between dates, no limit

			# Instead of 'None', print 'inf' when searching unlimited messages
			num_str = str(num_messages) if num_messages is not None else "inf"

			app_info = await bot.application_info()
			total = 0
			print(server)
			print("num_messages = "+ str(num_messages))
			print("bot.guilds = " + str(bot.guilds))
			print("bot.user = " + str(bot.user))
			print("Nom del server = " + str(server))

			for g in bot.guilds:
				print(g.name)
				if g.name == server:
					print(
						f"Connected to {g.name} as {bot.user},"
						f" emissary of {app_info.owner.name}\n"
					)
					await message.channel.send(
						f"Connected to {g.name} as {bot.user},"
						f" emissary of {app_info.owner.name}\n"
					)
					text_channels = g.text_channels
					#text_channels = "[<TextChannel id=1031567338430017570 name='pujar-fixers' position=4 nsfw=False news=False category_id=1031567338430017569>]"
					print("text_chanels = "+ str(text_channels))
					for c in g.text_channels:
						print("channels = " + str(channels))
						#if channels is None or c.name in channels:
						if channels == None or c.name in channels or channels == ("(None,)") or c.name in channels:
						#if channels == "None," or "pujar-fixers" in channels:
							await message.channel.send("channels1 = " + str(channels))
							count = 0
							if before is None and after is None:
								print(
									f"> Looking at last {num_str} messages"
									f" in {c.name}..."
								)
								await message.channel.send(
									f"> Looking at last {num_str} messages"
									f" in {c.name}..."
								)
							elif before is not None and after is not None:
								print(
									#f"> Looking at all messages between {before:(%Y-%m-%d)}"
									#f" and {after:%Y-%m-%d} in {c.name}..."
								)
								await message.channel.send(
									#f"> Looking at all messages between {before:%Y-%m-%d}"
									#f" and {after:%Y-%m-%d} in {c.name}..."
								)
							elif before is not None:
								print(
									f"> Looking at last {num_str} before"
									f" {before:%Y-%m-%d} messages in {c.name}..."
								)
								await message.channel.send(
									f"> Looking at last {num_str} before"
									f" {before:%Y-%m-%d} messages in {c.name}..."
								)
							elif after is not None:
								print(
									f"> Looking at first {num_str} after"
									f" {after:%Y-%m-%d} messages in {c.name}..."
								)
								await message.channel.send(
									f"> Looking at first {num_str} after"
									f" {after:%Y-%m-%d} messages in {c.name}..."
								)

							async for m in c.history(
								limit=num_messages, after=after, before=before
							):
								for a in m.attachments:
									if (
										(
											filetypes is None
											or a.filename.split(".")[-1] in filetypes
										)
										and (
											include_str is None or include_str in a.filename
										)
										and (
											exclude_str is None
											or exclude_str not in a.filename
										)
									):
										if verbose:
											print(f" > Found {a.filename}")
											await message.channel.send(f" > Found {a.filename}")
										count += 1
										fname = (
											m.author.name.replace(" ", "_")
											+ "__"
											+ a.filename
											if prepend_user
											else a.filename
										)
										fname = os.path.join(output_dir, fname)
										if not dry_run:
											await a.save(fname)

							print(f" >> Found {count} files.")
							await message.channel.send(f" >> Found {count} files.")
							total += count
				await message.channel.send("dry_run = " + str(dry_run))
			if dry_run:
				print(f"\n**** Dry run! 0 of {total} files saved!")
				await message.channel.send(f"\n**** Dry run! 0 of {total} files saved!")
			else:
				print(f"\n**** Saved {total} files to {output_dir}")
				await message.channel.send(f"\n**** Saved {total} files to {output_dir}")

# EXECUTES THE BOT WITH THE SPECIFIED TOKEN. TOKEN HAS BEEN REMOVED AND USED JUST AS AN EXAMPLE.
bot.run("MTAzMTU2MTM2MjAyOTE1MDM2OA.GsbkhI.LH7IIW_Hw8TVIaedYiAZnn3u1bcQUquhIai6eg")






