#!/usr/bin/python3

dir='/sys/class/power_supply/BAT0/'

with open(dir + 'power_now', 'r') as f:
	current = int(f.read()) / 1000000.0
with open(dir + 'voltage_now', 'r') as f:
	voltage = int(f.read()) / 1000000.0
wattage = voltage * current
# print('{0:.2f}V {1:.2f}A {2:.2f}W'.format(voltage, current, wattage))
print('{0:.2f}W'.format(wattage))