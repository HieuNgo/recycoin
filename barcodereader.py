# import the necessary packages
from imutils.video import VideoStream
from pyzbar import pyzbar
import argparse
import datetime
import imutils
import time
import cv2
import threading
from time import sleep


def barcodereader(frame):
    # initialize the video stream and allow the camera sensor to warm up
    # open the output CSV file for writing and initialize the set of
    # barcodes found thus far
    csv = open('barcode.csv', "w")

    # find the barcodes in the frame and decode each of the barcodes
    barcodes = pyzbar.decode(frame)
    # loop over the detected barcodes
    if len(barcodes) > 0:
        barcode = barcodes[0]
        # extract the bounding box location of the barcode and draw
        # the bounding box surrounding the barcode on the image
        (x, y, w, h) = barcode.rect
        cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 2)

        # the barcode data is a bytes object so if we want to draw it
        # on our output image we need to convert it to a string first
        barcodeData = barcode.data.decode("utf-8")
        barcodeType = barcode.type

        # if the barcode text is currently not in our CSV file, write
        # the timestamp + barcode to disk and update the set
        csv.write("{},{}\n".format(datetime.datetime.now(), barcodeData))
        csv.flush()
        # TODO:
        # search for item in database
        # plus point for user
        # close the output CSV file do a bit of cleanup
        print("[INFO] cleaning up...")
        return barcodeData
    return 0
